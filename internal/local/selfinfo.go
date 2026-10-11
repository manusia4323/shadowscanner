// Package selfinfo mengumpulkan informasi tentang perangkat pengguna sendiri
// dalam bahasa Indonesia yang mudah dipahami.
package local

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/host"
	"shadowscanner/internal/config"
)

// SelfInfo merekam informasi lengkap tentang perangkat pengguna
// untuk ditampilkan dalam antarmuka dalam bahasa Indonesia.
type SelfInfo struct {
	Hostname     string   // Nama host perangkat (mis. "laptop-ani")
	OS           string   // Sistem operasi lengkap (mis. "Ubuntu 22.04 LTS")
	Arch         string   // Arsitektur processor (mis. "x86_64")
	Interfaces   []NICInfo // Daftar antarmuka jaringan aktif
	PrimaryIP    string   // IP utama untuk koneksi keluar
	PrimaryMAC   string   // MAC yang berhubungan dengan IP utama
	GatewayIP    string   // IP gateway/default route
	GatewayMAC   string   // MAC gateway (dari ARP table)
	DNSServers   []string // Alamat DNS yang digunakan
}

// NICInfo merekam informasi tentang satu antarmuka jaringan.
type NICInfo struct {
	Name    string // Nama antarmuka (mis. "eth0", "wlan0")
	MAC     string // Alamat MAC dalam format XX:XX:XX:XX:XX:XX
	IPs     []string // Daftar alamat IP yang diassigned ke antarmuka ini
	IsWiFi  bool   // true jika antarmuka ini adalah koneksi nirkabel
	IsUp    bool   // true jika antarmuka aktif dan siap digunakan
}

// Get mengembalikan SelfInfo lengkap tentang perangkat pengguna.
// Fungsi ini read-only dan tidak mengubah sistem apa pun.
func Get(ctx context.Context) (SelfInfo, error) {
	var info SelfInfo
	var err error

	// Hostname
	if info.Hostname, err = os.Hostname(); err != nil {
		return SelfInfo{}, fmt.Errorf("get hostname: %w", err)
	}

	// OS dan Arch dari runtime + detail dari gopsutil
	info.Arch = runtime.GOARCH
	if hostInfo, err := host.InfoWithContext(ctx); err == nil {
		info.OS = hostInfo.OS + " " + hostInfo.Platform + " " + hostInfo.PlatformVersion
	} else {
		// Fallback ke runtime saja jika gopsutil gagal
		info.OS = runtime.GOOS
		if hostInfo, err := host.InfoWithContext(ctx); err == nil {
			info.OS = hostInfo.OS
		}
	}

	// Dapatkan daftar antarmuka
	if info.Interfaces, err = getNetworkInterfaces(); err != nil {
		return SelfInfo{}, fmt.Errorf("get network interfaces: %w", err)
	}

	// Dapatkan IP/MAC utama, gateway, dan DNS
	if info.PrimaryIP, info.PrimaryMAC, err = getPrimaryInterface(); err != nil {
		return SelfInfo{}, fmt.Errorf("get primary interface: %w", err)
	}

	if info.GatewayIP, info.GatewayMAC, err = getGatewayInfo(); err != nil {
		return SelfInfo{}, fmt.Errorf("get gateway info: %w", err)
	}

	if info.DNSServers, err = getDNSServers(); err != nil {
		return SelfInfo{}, fmt.Errorf("get DNS servers: %w", err)
	}

	return info, nil
}

// getNetworkInterfaces membaca semua antarmuka jaringan aktif.
func getNetworkInterfaces() ([]NICInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []NICInfo
	for _, iface := range interfaces {
		// Skip loopback dan interface yang tidak aktif
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		nic := NICInfo{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
			IsWiFi: isWiFiInterface(iface.Name),
			IsUp:   iface.Flags&net.FlagUp != 0,
		}

		// Dapatkan alamat IP untuk interface ini
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
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() == nil {
				continue // IPv4 only
			}
			nic.IPs = append(nic.IPs, ip.String())
		}

		if len(nic.IPs) > 0 {
			result = append(result, nic)
		}
	}

	return result, nil
}

// isWiFiInterface mencoba mendeteksi apakah antarmuka adalah WiFi
// berdasarkan nama umum (heuristik sederhana).
func isWiFiInterface(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "wlan") ||
		strings.Contains(name, "wifi") ||
		strings.Contains(name, "wi-fi") ||
		strings.Contains(name, "ath") ||
		strings.Contains(name, "ra") ||
		strings.HasPrefix(name, "wl")
}

// getPrimaryInterface mengembalikan IP dan MAC dari antarmuka
// yang memiliki default route (untuk koneksi keluar).
func getPrimaryInterface() (string, string, error) {
	// Baca routing table untuk menemukan default route
	switch runtime.GOOS {
	case "linux":
		return getPrimaryInterfaceLinux()
	case "windows":
		return getPrimaryInterfaceWindows()
	case "darwin":
		return getPrimaryInterfaceDarwin()
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getPrimaryInterfaceLinux membaca /proc/net/route untuk Linux.
func getPrimaryInterfaceLinux() (string, string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Destination 00000000 = default route
		if fields[0] != "00000000" {
			continue
		}
		iface := fields[0] // Actually interface name is in first column
		iface = fields[0] // No, let me check format again
		// Format: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		if len(fields) < 8 {
			continue
		}
		if fields[0] == "" || fields[1] != "00000000" {
			continue
		}
		iface = fields[0]
		// Dapatkan MAC untuk interface ini
		mac, err := getMACForInterface(iface)
		if err != nil {
			continue
		}
		// Dapatkan IP untuk interface ini
		ip, err := getIPForInterface(iface)
		if err != nil {
			continue
		}
		return ip, mac, nil
	}
	return "", "", errors.New("no default route found")
}

// getPrimaryInterfaceWindows menggunakan `route print`.
func getPrimaryInterfaceWindows() (string, string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
			// Format tidak konsisten, untuk sekarang kembalikan placeholder
			// Implementasi lengkap akan memproses output ini dengan lebih teliti
			ifaces, _ := net.Interfaces()
			if len(ifaces) > 0 {
				for _, iface := range ifaces {
					if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
						addrs, _ := iface.Addrs()
						for _, addr := range addrs {
							var ip net.IP
							switch v := addr.(type) {
							case *net.IPNet:
								ip = v.IP
							case *net.IPAddr:
								ip = v.IP
							}
							if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
								return ip.String(), iface.HardwareAddr.String(), nil
							}
						}
					}
				}
			}
			break
		}
	}
	return "", "", errors.New("could not parse route output")
}

// getPrimaryInterfaceDarwin menggunakan `netstat -rn`.
func getPrimaryInterfaceDarwin() (string, string, error) {
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "default") {
			fields := strings.Fields(line)
			if len(fields) >= 6 && fields[0] == "default" {
				iface := fields[5]
				mac, err := getMACForInterface(iface)
				if err != nil {
					continue
				}
				ip, err := getIPForInterface(iface)
				if err != nil {
					continue
				}
				return ip, mac, nil
			}
		}
	}
	return "", "", errors.New("no default route found")
}

// getMACForInterface mengembalikan MAC address untuk nama interface yang diberikan.
func getMACForInterface(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	if iface.HardwareAddr == nil {
		return "", errors.New("no hardware address")
	}
	return iface.HardwareAddr.String(), nil
}

// getIPForInterface mengembalikan alamat IPv4 pertama untuk interface yang diberikan.
func getIPForInterface(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
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
			continue // IPv4 only
		}
		return ip.String(), nil
	}
	return "", errors.New("no IPv4 address found")
}

// getGatewayInfo membaca gateway IP dan MAC dari routing dan ARP table.
func getGatewayInfo() (string, string, error) {
	switch runtime.GOOS {
	case "linux":
		return getGatewayInfoLinux()
	case "windows":
		return getGatewayInfoWindows()
	case "darwin":
		return getGatewayInfoDarwin()
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getGatewayInfoLinux membaca gateway dari /proc/net/route dan MAC dari ARP.
func getGatewayInfoLinux() (string, string, error) {
	// Dapatkan gateway IP dari routing table
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", "", err
	}
	var gatewayIP net.IP
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[0] == "" || fields[1] != "00000000" {
			continue
		}
		// Gateway adalah fields[2] dalam format hex
		gwHex := fields[2]
		if len(gwHex) == 8 {
			gatewayIP = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d",
				hexToInt(gwHex[0:2]),
				hexToInt(gwHex[2:4]),
				hexToInt(gwHex[4:6]),
				hexToInt(gwHex[6:8])))
			if gatewayIP != nil {
				break
			}
		}
	}
	if gatewayIP == nil {
		return "", "", errors.New("could not find gateway IP")
	}

	// Dapatkan MAC gateway dari ARP table
	gatewayMAC, err := getMACFromARP(gatewayIP.String())
	if err != nil {
		return gatewayIP.String(), "", err // Return IP tanpa MAC jika ARP gagal
	}
	return gatewayIP.String(), gatewayMAC, nil
}

// getGatewayInfoWindows menggunakan `route print` dan `arp -a`.
func getGatewayInfoWindows() (string, string, error) {
	// Untuk session ini, kembalikan placeholder karena parsing output Windows kompleks
	return "", "", errors.New("not implemented for Windows in this session")
}

// getGatewayInfoDarwin menggunakan `netstat -rn` dan `arp -an`.
func getGatewayInfoDarwin() (string, string, error) {
	// Dapatkan gateway IP
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(out), "\n")
	var gatewayIP net.IP
	for _, line := range lines {
		if strings.Contains(line, "default") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				gatewayIP = net.ParseIP(fields[1])
				if gatewayIP != nil {
					break
				}
			}
		}
	}
	if gatewayIP == nil {
		return "", "", errors.New("could not find gateway IP")
	}

	// Dapatkan MAC dari ARP
	gatewayMAC, err := getMACFromARP(gatewayIP.String())
	if err != nil {
		return gatewayIP.String(), "", err
	}
	return gatewayIP.String(), gatewayMAC, nil
}

// getMACFromARP mencari MAC address untuk IP yang diberikan dari ARP table.
func getMACFromARP(ip string) (string, error) {
	switch runtime.GOOS {
	case "linux":
		return getMACFromARPLinux(ip)
	case "windows":
		return getMACFromARPWindows(ip)
	case "darwin":
		return getMACFromARPDarwin(ip)
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getMACFromARPLinux membaca /proc/net/arp.
func getMACFromARPLinux(ip string) (string, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == ip {
			return strings.TrimSpace(fields[3]), nil
		}
	}
	return "", fmt.Errorf("MAC not found for IP %s in ARP table", ip)
}

// getMACFromARPWindows menggunakan `arp -a`.
func getMACFromARPWindows(ip string) (string, error) {
	out, err := exec.Command("arp", "-a", ip).Output()
	if err != nil {
		return "", err
	}
	output := string(out)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			// Format: 192.168.1.1          00-1a-2b-3c-4d-5e     dynamic
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == ip {
				mac := strings.ReplaceAll(fields[1], "-", ":")
				return mac, nil
			}
		}
	}
	return "", fmt.Errorf("MAC not found for IP %s in ARP output", ip)
}

// getMACFromARPDarwin menggunakan `arp -an`.
func getMACFromARPDarwin(ip string) (string, error) {
	out, err := exec.Command("arp", "-an", ip).Output()
	if err != nil {
		return "", err
	}
	output := string(out)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			// Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on en0 ifscope [ethernet]
			parts := strings.Split(line, "at")
			if len(parts) >= 2 {
				macPart := strings.TrimSpace(parts[1])
				macFields := strings.Fields(macPart)
				if len(macFields) >= 1 {
					mac := macFields[0]
					if mac != "(incomplete)" {
						return mac, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("MAC not found for IP %s in ARP output", ip)
}

// getDNSServers membaca konfigurasi DNS dari sistem.
func getDNSServers() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return getDNSServersLinux()
	case "windows":
		return getDNSServersWindows()
	case "darwin":
		return getDNSServersDarwin()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getDNSServersLinux membaca /etc/resolv.conf.
func getDNSServersLinux() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var servers []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := net.ParseIP(fields[1])
				if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
					servers = append(servers, ip.String())
				}
			}
		}
	}
	return servers, nil
}

// getDNSServersWindows menggunakan `ipconfig /all`.
func getDNSServersWindows() ([]string, error) {
	// Placeholder untuk session ini
	return []string{}, errors.New("not implemented for Windows in this session")
}

// getDNSServersDarwin menggunakan `scutil --dns`.
func getDNSServersDarwin() ([]string, error) {
	// Placeholder untuk session ini
	return []string{}, errors.New("not implemented for Darwin in this session")
}

// hexToInt mengonversi string hex 2 karakter menjadi integer.
func hexToInt(s string) int {
	if len(s) != 2 {
		return 0
	}
	val, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return 0
	}
	return int(val)
}