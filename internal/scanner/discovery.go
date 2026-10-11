// Package discovery implements passive network discovery for devices on the
// local subnet. It uses ARP table reading, ICMP probing, and hostname
// resolution to build a list of devices without injecting malicious traffic.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device represents a discovered device on the local network.
type Device struct {
	MAC      string
	IP       string
	Hostname string
	Vendor   string
}

// Discovery manages the discovery process using configuration.
type Discovery struct {
	cfg *config.Config
}

// NewDiscovery creates a new Discovery instance with the given config.
func NewDiscovery(cfg *config.Config) (*Discovery, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	return &Discovery{cfg: cfg}, nil
}

// Scan performs a single discovery sweep and returns found devices.
// It respects the provided context for cancellation.
func (d *Discovery) Scan(ctx context.Context) ([]Device, error) {
	// 1. Determine user's own IP, MAC, and subnet for each active non-loopback interface.
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var localAddrs []interfaceAddr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue // skip loopback and down interfaces
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue // skip interface if we can't read addresses
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() == nil {
				continue // IPv4 only for now
			}
			mac := iface.HardwareAddr.String()
			if len(mac) == 0 {
				continue
			}
			// Assume /24 subnet for simplicity — common for local networks.
			// The IP's network portion with a /24 mask gives us the subnet base.
			mask := net.CIDRMask(24, 32)
			network := ip.Mask(mask)
			localAddrs = append(localAddrs, interfaceAddr{
				iface:  iface,
				ip:     ip,
				mac:    mac,
				network: network,
			})
		}
	}

	if len(localAddrs) == 0 {
		return nil, errors.New("no suitable network interfaces found")
	}

	// 2. Read ARP table for each interface to get initial neighbor cache.
	arpEntries, err := readARPTable()
	if err != nil {
		return nil, fmt.Errorf("read ARP table: %w", err)
	}

	// 3. For each local interface, send ICMP echo to each host in subnet to populate ARP.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32) // limit concurrency to 32 goroutines
	discovered := make(map[string]Device) // keyed by MAC
	var mu sync.Mutex

	for _, local := range localAddrs {
		// Generate list of IPs in subnet (excluding .0 and .255)
		for i := 1; i < 255; i++ {
			targetIP := make(net.IP, 4)
			copy(targetIP, local.network)
			targetIP[3] += byte(i)
			// Skip the user's own IP
			if targetIP.Equal(local.ip) {
				continue
			}
			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
				// Send single ICMP echo with 500 ms timeout
				if err := pingHostIP(ip, 500*time.Millisecond); err != nil {
					// Ignore errors; host may be down or not responding
					return
				}
			}(targetIP)
		}
	}
	wg.Wait() // wait for all pings to complete

	// 4. Re-read ARP table to get newly populated entries.
	newARP, err := readARPTable()
	if err != nil {
		return nil, fmt.Errorf("re-read ARP table: %w", err)
	}
	// Merge existing and new ARP entries
	merged := make(map[string]bool)
	for _, e := range arpEntries {
		merged[e.mac] = true
	}
	for _, e := range newARP {
		merged[e.mac] = true
	}
	var mergedEntries []arpEntry
	for mac := range merged {
		// Find the entry with this MAC
		for _, e := range arpEntries {
			if e.mac == mac {
				mergedEntries = append(mergedEntries, e)
				break
			}
		}
		for _, e := range newARP {
			if e.mac == mac {
				// Already added if from arpEntries; skip duplicate
				// Actually we want unique entries - take first seen
				added := false
				for _, me := range mergedEntries {
					if me.mac == mac {
						added = true
						break
					}
				}
				if !added {
					mergedEntries = append(mergedEntries, e)
				}
				break
			}
		}
	}

	// 5. For each ARP entry, resolve hostname and vendor.
	for _, entry := range mergedEntries {
		// Skip if MAC is zero or broadcast
		if entry.mac == "00:00:00:00:00:00" || entry.mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		// Skip if we already have this MAC (deduplicate)
		if _, exists := discovered[entry.mac]; exists {
			continue
		}

		// Resolve hostname via reverse DNS
		hostname := ""
		names, err := net.LookupAddr(entry.ip.String())
		if err == nil && len(names) > 0 {
			hostname = strings.TrimSuffix(names[0], ".") // remove trailing dot
		}
		if hostname == "" {
			// Try mDNS query for .local names — fallback to empty in this session
			hostname = queryMDNS(entry.ip)
		}

		// Lookup vendor from MAC OUI
		vendor := lookupVendor(entry.mac)

		device := Device{
			MAC:      entry.mac,
			IP:       entry.ip.String(),
			Hostname: hostname,
			Vendor:   vendor,
		}
		mu.Lock()
		discovered[entry.mac] = device
		mu.Unlock()
	}

	// 6. Skip the user's own device from results (but keep info accessible via Self)
	var results []Device
	for _, dev := range discovered {
		isSelf := false
		for _, local := range localAddrs {
			if dev.MAC == local.mac || dev.IP == local.ip.String() {
				isSelf = true
				break
			}
		}
		if !isSelf {
			results = append(results, dev)
		}
	}

	return results, nil
}

// Self returns the user's own device info (IP, MAC, hostname).
func (d *Discovery) Self(ctx context.Context) (Device, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return Device{}, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			mac := iface.HardwareAddr.String()
			if len(mac) == 0 {
				continue
			}
			hostname, _ := os.Hostname()
			return Device{
				MAC:      mac,
				IP:       ip.String(),
				Hostname: hostname,
				Vendor:   "",
			}, nil
		}
	}
	return Device{}, errors.New("no suitable interface found for self")
}

// interfaceAddr holds local interface information.
type interfaceAddr struct {
	iface    net.Interface
	ip       net.IP
	mac      string
	network  net.IP // network address (e.g., 192.168.1.0)
}

// pingHostIP sends a single ICMP echo request to the given IP with timeout.
// Uses os/exec to call platform ping command. On Linux: ping -c 1 -W <timeout_sec>.
func pingHostIP(ip net.IP, timeout time.Duration) error {
	// On Linux, ping -c 1 -W <seconds> (fractional allowed)
	// Convert timeout to seconds with 1 decimal place
	timeoutStr := strconv.FormatFloat(timeout.Seconds(), 'f', 1, 64)
	cmd := exec.Command("ping", "-c", "1", "-W", timeoutStr, ip.String())
	output, err := cmd.Output()
	if err != nil {
		// ping may fail if host not reachable or ICMP blocked; either way continue
		_ = output
		return err
	}
	_ = output
	return nil
}

// queryMDNS attempts to resolve hostname via mDNS for .local names.
// For this session, returns empty string (full implementation uses hashicorp/mdns).
func queryMDNS(ip net.IP) string {
	// TODO: implement mDNS query using hashicorp/mdns in future session
	return ""
}

// lookupVendor returns vendor name from MAC OUI.
// For this session, uses a small embedded map. In practice, load internal/oui.csv.
func lookupVendor(mac string) string {
	mac = strings.TrimSpace(mac)
	if len(mac) < 8 {
		return ""
	}
	oui := strings.ToUpper(mac[0:8])
	switch oui {
	case "00:1A:7D":
		return "Apple"
	case "00:25:90":
		return "Samsung"
	case "3C:5A:B4":
		return "Google"
	case "DC:A6:32":
		return "Amazon"
	case "00:E0:4C":
		return "Realtek"
	case "00:0C:29":
		return "VMware"
	case "00:50:56":
		return "VMware"
	case "00:05:69":
		return "Intel"
	case "00:1B:21":
		return "Intel"
	case "00:22:4D":
		return "Red Hat"
	case "00:23:AE":
		return "Dell"
	case "00:26:B9":
		return "TP-Link"
	case "A0:36:9F":
		return "Cisco"
	case "B8:27:EB":
		return "Raspberry Pi"
	case "F0:18:97":
		return "OnePlus"
	case "AC:DE:4C":
		return "HP"
	case "00:1F:33":
		return "Intel Corporate"
	case "9C:D9:1D":
		return "Apple iPhone"
	case "F8:1A:5E":
		return "Xiaomi"
	case "B4:65:1E":
		return "LG Electronics"
	case "70:5B:CB":
		return "Sony"
	case "D0:73:D3":
		return "Intel Corporate"
	case "E8:9A:37":
		return "ASUSTek"
	case "00:0B:87":
		return "Netgear"
	case "00:1E:52":
		return "Dell"
	case "00:21:5B":
		return "Dell"
	case "00:25:2C":
		return "Intel Corporate"
	}
	return ""
}

// readARPTable reads the system ARP table. Tries /proc/net/arp on Linux first,
// then falls back to `arp -a` command.
func readARPTable() ([]arpEntry, error) {
	// Try Linux /proc/net/arp first
	if entries, err := readProcNetARP(); err == nil {
		return entries, nil
	}
	// Fallback to arp -a command
	return readARPCommand()
}

// readProcNetARP parses /proc/net/arp on Linux.
// Format: IP HWtype Flags HWaddress Mask Iface
// Example line: 192.168.1.1 0x1 0x2 00:11:22:33:44:55 * eth0
func readProcNetARP() ([]arpEntry, error) {
	data, err := readFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var entries []arpEntry
	for i := 1; i < len(lines); i++ { // skip header
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ipStr := fields[0]
		hwType := fields[1]
		macStr := fields[3]
		// Only consider Ethernet (HW type 1)
		if hwType != "0x1" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		mac := strings.TrimSpace(macStr)
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		// Basic MAC format validation
		if len(mac) < 17 {
			continue
		}
		entries = append(entries, arpEntry{ip: ip, mac: mac})
	}
	return entries, nil
}

// readFile reads file content via cat command.
func readFile(path string) ([]byte, error) {
	out, err := exec.Command("cat", path).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readARPCommand falls back to executing `arp -a` and parsing output.
func readARPCommand() ([]arpEntry, error) {
	// Try arp -a first
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err == nil {
		return parseARPOutput(string(output))
	}
	// If arp not available, try ip neigh
	if strings.Contains(err.Error(), "exec: \"arp\"") || strings.Contains(err.Error(), "no such file or directory") {
		cmd = exec.Command("ip", "neigh")
		output, err = cmd.Output()
		if err == nil {
			return parseIPNeighOutput(string(output))
		}
	}
	return nil, errors.New("could not read ARP table")
}

// parseARPOutput parses the output of `arp -a` or similar format.
func parseARPOutput(output string) ([]arpEntry, error) {
	var entries []arpEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Look for IP and MAC in line
		// Common format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
		ip := extractIPfromLine(line)
		mac := extractMACfromLine(line)
		if ip != nil && mac != "" && mac != "00:00:00:00:00:00" {
			entries = append(entries, arpEntry{ip: ip, mac: mac})
		}
	}
	return entries, nil
}

// extractIPfromLine extracts an IP address from a line of text.
func extractIPfromLine(line string) net.IP {
	parts := strings.Split(line, ".")
	if len(parts) >= 4 {
		for i := 0; i <= len(parts)-4; i++ {
			candidate := parts[i] + "." + parts[i+1] + "." + parts[i+2] + "." + parts[i+3]
			if ip := net.ParseIP(candidate); ip != nil && !ip.IsLoopback() {
				return ip
			}
		}
	}
	return nil
}

// extractMACfromLine extracts a MAC address from a line of text.
func extractMACfromLine(line string) string {
	// Look for xx:xx:xx:xx:xx:xx pattern
	// Find colon-separated hex groups
	start := strings.Index(line, ":")
	if start < 0 {
		return ""
	}
	// Try to extract 6 colon-separated hex pairs
	end := start + 17 // xx:xx:xx:xx:xx:xx is 17 chars
	if end > len(line) {
		end = len(line)
	}
	candidate := line[start:end]
	parts := strings.Split(candidate, ":")
	if len(parts) == 6 {
		valid := true
		for _, p := range parts {
			if len(p) != 2 {
				valid = false
				break
			}
			for _, c := range p {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					valid = false
					break
				}
			}
			if !valid {
				break
			}
		}
		if valid {
			return candidate
		}
	}
	return ""
}

// parseIPNeighOutput parses output of `ip neigh` command.
// Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACH
func parseIPNeighOutput(output string) ([]arpEntry, error) {
	var entries []arpEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		ip := net.ParseIP(parts[0])
		if ip == nil {
			continue
		}
		var mac string
		for i, p := range parts {
			if p == "lladdr" && i+1 < len(parts) {
				mac = parts[i+1]
				break
			}
		}
		if mac != "" && mac != "00:00:00:00:00:00" {
			entries = append(entries, arpEntry{ip: ip, mac: mac})
		}
	}
	return entries, nil
}