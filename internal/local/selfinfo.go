// Package local mengumpulkan informasi tentang perangkat pengguna sendiri,
// koneksi jaringan aktif, dan proses yang membuka soket.
package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/host"
)

// SelfInfo merekam informasi lengkap tentang perangkat pengguna
// untuk ditampilkan dalam antarmuka dalam bahasa Indonesia.
type SelfInfo struct {
	Hostname   string    // Nama host perangkat (mis. "laptop-ani")
	OS         string    // Sistem operasi lengkap (mis. "Ubuntu 22.04 LTS")
	Arch       string    // Arsitektur processor (mis. "amd64")
	Interfaces []NICInfo // Daftar antarmuka jaringan aktif
	PrimaryIP  string    // IP utama untuk koneksi keluar
	PrimaryMAC string    // MAC yang berhubungan dengan IP utama
	GatewayIP  string    // IP gateway/default route
	GatewayMAC string    // MAC gateway (dari ARP table)
	DNSServers []string  // Alamat DNS yang digunakan
}

// NICInfo merekam informasi tentang satu antarmuka jaringan.
type NICInfo struct {
	Name   string   // Nama antarmuka (mis. "eth0", "wlan0")
	MAC    string   // Alamat MAC dalam format XX:XX:XX:XX:XX:XX
	IPs    []string // Daftar alamat IP yang diassign ke antarmuka ini
	IsWiFi bool     // true jika antarmuka ini adalah koneksi nirkabel
	IsUp   bool     // true jika antarmuka aktif dan siap digunakan
}

// Get mengembalikan SelfInfo lengkap tentang perangkat pengguna.
// Fungsi ini read-only dan tidak mengubah sistem apa pun.
func Get(ctx context.Context) (SelfInfo, error) {
	var info SelfInfo
	var err error

	// Hostname
	info.Hostname, err = os.Hostname()
	if err != nil {
		return SelfInfo{}, fmt.Errorf("gagal mendapatkan hostname: %w", err)
	}

	// Arsitektur
	info.Arch = runtime.GOARCH

	// OS info dari gopsutil
	if hostInfo, err := host.InfoWithContext(ctx); err == nil {
		platform := hostInfo.Platform
		if platform == "" {
			platform = hostInfo.OS
		}
		version := hostInfo.PlatformVersion
		if version != "" {
			info.OS = fmt.Sprintf("%s %s", platform, version)
		} else {
			info.OS = platform
		}
	} else {
		info.OS = runtime.GOOS
	}

	// Antarmuka jaringan
	info.Interfaces, err = getNetworkInterfaces()
	if err != nil {
		return SelfInfo{}, fmt.Errorf("gagal membaca antarmuka jaringan: %w", err)
	}

	// IP dan MAC utama
	info.PrimaryIP, info.PrimaryMAC, _ = getPrimaryInterface()

	// Gateway IP dan MAC
	info.GatewayIP, info.GatewayMAC, _ = getGatewayInfo()

	// DNS servers
	info.DNSServers, _ = getDNSServers()

	return info, nil
}

// getNetworkInterfaces membaca semua antarmuka jaringan non-loopback yang aktif.
func getNetworkInterfaces() ([]NICInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []NICInfo
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		isUp := iface.Flags&net.FlagUp != 0
		nic := NICInfo{
			Name:   iface.Name,
			MAC:    iface.HardwareAddr.String(),
			IsWiFi: isWiFiInterface(iface.Name),
			IsUp:   isUp,
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
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil {
				nic.IPs = append(nic.IPs, ip.String())
			}
		}

		result = append(result, nic)
	}

	return result, nil
}

// isWiFiInterface mendeteksi apakah antarmuka merupakan koneksi WiFi berdasarkan pola nama.
func isWiFiInterface(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "wlan") ||
		strings.Contains(lower, "wifi") ||
		strings.Contains(lower, "wi-fi") ||
		strings.Contains(lower, "ath") ||
		strings.Contains(lower, "ra") ||
		strings.HasPrefix(lower, "wl")
}

// getPrimaryInterface mencari IP dan MAC antarmuka rute utama (default route).
func getPrimaryInterface() (string, string, error) {
	switch runtime.GOOS {
	case "linux":
		return getPrimaryInterfaceLinux()
	case "windows":
		return getPrimaryInterfaceWindows()
	case "darwin":
		return getPrimaryInterfaceDarwin()
	default:
		return getFallbackInterface()
	}
}

// getPrimaryInterfaceLinux membaca /proc/net/route untuk rute 00000000.
func getPrimaryInterfaceLinux() (string, string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return getFallbackInterface()
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			ifaceName := fields[0]
			ip, mac := getIfaceIPAndMAC(ifaceName)
			if ip != "" {
				return ip, mac, nil
			}
		}
	}

	return getFallbackInterface()
}

// getPrimaryInterfaceWindows menggunakan `route print 0.0.0.0`.
func getPrimaryInterfaceWindows() (string, string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	out, err := cmd.Output()
	if err != nil {
		return getFallbackInterface()
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Format IPv4 Route Table: Network Destination Netmask Gateway Interface Metric
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			ip := fields[3]
			if net.ParseIP(ip) != nil {
				mac := findMACByIP(ip)
				return ip, mac, nil
			}
		}
	}

	return getFallbackInterface()
}

// getPrimaryInterfaceDarwin menggunakan `netstat -rn`.
func getPrimaryInterfaceDarwin() (string, string, error) {
	cmd := exec.Command("netstat", "-rn")
	out, err := cmd.Output()
	if err != nil {
		return getFallbackInterface()
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[0] == "default" {
			ifaceName := fields[5]
			ip, mac := getIfaceIPAndMAC(ifaceName)
			if ip != "" {
				return ip, mac, nil
			}
		}
	}

	return getFallbackInterface()
}

// getFallbackInterface mengembalikan antarmuka aktif non-loopback pertama.
func getFallbackInterface() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}

	for _, iface := range ifaces {
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
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				return ip.String(), iface.HardwareAddr.String(), nil
			}
		}
	}

	return "", "", errors.New("tidak ada antarmuka jaringan yang sesuai")
}

// getIfaceIPAndMAC mengambil IP IPv4 dan MAC dari antarmuka bernama tertentu.
func getIfaceIPAndMAC(name string) (string, string) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", ""
	}
	mac := iface.HardwareAddr.String()

	addrs, err := iface.Addrs()
	if err != nil {
		return "", mac
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
			return ip.String(), mac
		}
	}
	return "", mac
}

// findMACByIP mencari MAC dari interface yang memiliki IP tersebut.
func findMACByIP(targetIP string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), targetIP) {
				return iface.HardwareAddr.String()
			}
		}
	}
	return ""
}

// getGatewayInfo membaca gateway IP dan MAC dari routing table dan ARP.
func getGatewayInfo() (string, string, error) {
	switch runtime.GOOS {
	case "linux":
		return getGatewayInfoLinux()
	case "windows":
		return getGatewayInfoWindows()
	case "darwin":
		return getGatewayInfoDarwin()
	default:
		return "", "", errors.New("sistem operasi tidak didukung untuk pencarian gateway")
	}
}

// getGatewayInfoLinux membaca rute 00000000 dari /proc/net/route lalu cari MAC di /proc/net/arp.
func getGatewayInfoLinux() (string, string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", "", err
	}

	var gwIP string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			gwHex := fields[2]
			if len(gwHex) == 8 {
				b0, _ := strconv.ParseInt(gwHex[6:8], 16, 64)
				b1, _ := strconv.ParseInt(gwHex[4:6], 16, 64)
				b2, _ := strconv.ParseInt(gwHex[2:4], 16, 64)
				b3, _ := strconv.ParseInt(gwHex[0:2], 16, 64)
				gwIP = fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
				break
			}
		}
	}

	if gwIP == "" {
		return "", "", errors.New("gateway IP tidak ditemukan")
	}

	gwMAC := findMACInARPTable(gwIP)
	return gwIP, gwMAC, nil
}

// getGatewayInfoWindows membaca route print.
func getGatewayInfoWindows() (string, string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gwIP := fields[2]
			if net.ParseIP(gwIP) != nil {
				gwMAC := findMACInARPTable(gwIP)
				return gwIP, gwMAC, nil
			}
		}
	}

	return "", "", errors.New("gateway IP tidak ditemukan di Windows")
}

// getGatewayInfoDarwin membaca netstat -rn.
func getGatewayInfoDarwin() (string, string, error) {
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return "", "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" {
			gwIP := fields[1]
			if net.ParseIP(gwIP) != nil {
				gwMAC := findMACInARPTable(gwIP)
				return gwIP, gwMAC, nil
			}
		}
	}

	return "", "", errors.New("gateway IP tidak ditemukan di macOS")
}

// findMACInARPTable membaca tabel ARP sistem untuk mencari MAC dari IP gateway.
func findMACInARPTable(targetIP string) string {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/net/arp"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines[1:] {
				fields := strings.Fields(line)
				if len(fields) >= 4 && fields[0] == targetIP {
					mac := fields[3]
					if mac != "00:00:00:00:00:00" {
						return mac
					}
				}
			}
		}
	}

	// Fallback ke arp -a atau arp -an
	arg := "-a"
	if runtime.GOOS == "darwin" {
		arg = "-an"
	}
	out, err := exec.Command("arp", arg).Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, targetIP) {
			fields := strings.Fields(line)
			for _, f := range fields {
				clean := strings.Trim(f, "()")
				clean = strings.ReplaceAll(clean, "-", ":")
				parts := strings.Split(clean, ":")
				if len(parts) == 6 {
					return clean
				}
			}
		}
	}

	return ""
}

// getDNSServers membaca daftar server DNS yang dikonfigurasi pada sistem.
func getDNSServers() ([]string, error) {
	switch runtime.GOOS {
	case "linux":
		return getDNSServersLinux()
	case "windows":
		return getDNSServersWindows()
	case "darwin":
		return getDNSServersDarwin()
	default:
		return nil, errors.New("sistem operasi tidak didukung untuk pencarian DNS")
	}
}

// getDNSServersLinux membaca /etc/resolv.conf.
func getDNSServersLinux() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := net.ParseIP(fields[1])
				if ip != nil && ip.To4() != nil {
					servers = append(servers, ip.String())
				}
			}
		}
	}
	return servers, nil
}

// getDNSServersWindows membaca ipconfig /all.
func getDNSServersWindows() ([]string, error) {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(out), "\n")
	capture := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, "DNS Servers") {
			capture = true
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ipStr := strings.TrimSpace(parts[1])
				if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
					servers = append(servers, ipStr)
				}
			}
			continue
		}
		if capture {
			if strings.Contains(line, ":") {
				capture = false
				continue
			}
			if ip := net.ParseIP(trimmed); ip != nil && ip.To4() != nil {
				servers = append(servers, trimmed)
			}
		}
	}
	return servers, nil
}

// getDNSServersDarwin membaca scutil --dns.
func getDNSServersDarwin() ([]string, error) {
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	seen := make(map[string]bool)
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ipStr := strings.TrimSpace(parts[1])
				if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil && !seen[ipStr] {
					seen[ipStr] = true
					servers = append(servers, ipStr)
				}
			}
		}
	}
	return servers, nil
}