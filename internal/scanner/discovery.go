// Package scanner menyediakan fungsi pemindaian defensif untuk jaringan lokal:
// penemuan perangkat (discovery), pemeriksaan port terbatas, sidik jari (fingerprinting),
// perkiraan jarak fisik, dan identifikasi penyedia layanan internet (ISP).
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"shadowscanner/internal/config"
)

// Device merepresentasikan satu perangkat yang terdeteksi di jaringan lokal pengguna.
type Device struct {
	MAC      string // Alamat MAC (format XX:XX:XX:XX:XX:XX)
	IP       string // Alamat IPv4 lokal
	Hostname string // Nama host dari reverse DNS atau mDNS
	Vendor   string // Nama pabrikan dari prefix OUI
}

// Discovery mengelola proses pemindaian dan penemuan perangkat pada subnet lokal pengguna.
type Discovery struct {
	cfg *config.Config
}

// NewDiscovery menciptakan instance Discovery baru dengan konfigurasi yang diberikan.
func NewDiscovery(cfg *config.Config) (*Discovery, error) {
	if cfg == nil {
		return nil, errors.New("konfigurasi tidak boleh nil")
	}
	return &Discovery{cfg: cfg}, nil
}

// subnetInterface menyimpan informasi antarmuka aktif dan subnet-nya.
type subnetInterface struct {
	iface   net.Interface
	ip      net.IP
	mac     string
	ipNet   *net.IPNet
	network net.IP
}

// Scan melakukan pemindaian pasif pada subnet lokal dan mengembalikan daftar perangkat.
// Seluruh operasi mematuhi pembatalan melalui context.Context.
func (d *Discovery) Scan(ctx context.Context) ([]Device, error) {
	slog.Debug("memulai pemindaian jaringan lokal pasif")

	// 1. Dapatkan antarmuka aktif non-loopback dan subnet lokalnya.
	subnets, err := getLocalSubnets()
	if err != nil {
		return nil, fmt.Errorf("gagal mendapatkan subnet lokal: %w", err)
	}
	if len(subnets) == 0 {
		return nil, errors.New("tidak ada antarmuka jaringan aktif yang memiliki alamat IPv4")
	}

	// 2. Baca tabel ARP awal.
	initialARP, err := readARPTable()
	if err != nil {
		slog.Debug("baca tabel ARP awal menemui kendala, melanjutkan", "error", err)
		initialARP = nil
	}

	// 3. Kirim probe ICMP echo tunggal (1 paket) ke host di subnet untuk memicu cache ARP.
	// Batasi konkuren maksimal 32 goroutine.
	if err := d.probeSubnets(ctx, subnets); err != nil {
		return nil, fmt.Errorf("probe subnet dibatalkan: %w", err)
	}

	// 4. Baca ulang tabel ARP untuk mengumpulkan perangkat yang baru terdeteksi.
	updatedARP, err := readARPTable()
	if err != nil && len(initialARP) == 0 {
		return nil, fmt.Errorf("baca ulang tabel ARP gagal: %w", err)
	}

	// Gabungkan entri ARP yang unik berdasarkan MAC.
	arpMap := make(map[string]string) // MAC -> IP
	for _, entry := range initialARP {
		if entry.mac != "" && entry.ip != "" {
			arpMap[strings.ToUpper(entry.mac)] = entry.ip
		}
	}
	for _, entry := range updatedARP {
		if entry.mac != "" && entry.ip != "" {
			arpMap[strings.ToUpper(entry.mac)] = entry.ip
		}
	}

	// 5. Kumpulkan daftar perangkat sendiri untuk dilewati dari hasil.
	selfMACs := make(map[string]bool)
	selfIPs := make(map[string]bool)
	for _, s := range subnets {
		selfMACs[strings.ToUpper(s.mac)] = true
		selfIPs[s.ip.String()] = true
	}

	// 6. Resolusi hostname dan pabrikan vendor untuk setiap perangkat yang ditemukan.
	var devices []Device
	for mac, ipStr := range arpMap {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Lewati alamat broadcast atau zero MAC
		if isIgnoredMAC(mac) {
			continue
		}

		// Lewati perangkat milik pengguna sendiri
		if selfMACs[mac] || selfIPs[ipStr] {
			continue
		}

		// Pastikan IP perangkat berada dalam salah satu subnet lokal pengguna
		targetIP := net.ParseIP(ipStr)
		if targetIP == nil || !isIPInSubnets(targetIP, subnets) {
			continue
		}

		// Resolusi hostname dengan batas waktu 1 detik
		hostname := resolveHostname(ctx, ipStr)

		// Lookup vendor dari MAC OUI
		vendor := LookupVendor(mac)

		devices = append(devices, Device{
			MAC:      mac,
			IP:       ipStr,
			Hostname: hostname,
			Vendor:   vendor,
		})
	}

	slog.Debug("pemindaian jaringan selesai", "total_perangkat", len(devices))
	return devices, nil
}

// Self mengembalikan informasi tentang perangkat pengguna sendiri (IP, MAC, hostname).
func (d *Discovery) Self() (Device, error) {
	hostname, _ := os.Hostname()
	subnets, err := getLocalSubnets()
	if err != nil || len(subnets) == 0 {
		return Device{}, errors.New("tidak dapat menemukan antarmuka aktif untuk perangkat sendiri")
	}

	primary := subnets[0]
	return Device{
		MAC:      strings.ToUpper(primary.mac),
		IP:       primary.ip.String(),
		Hostname: hostname,
		Vendor:   LookupVendor(primary.mac),
	}, nil
}

// getLocalSubnets mengumpulkan semua antarmuka non-loopback yang aktif beserta subnet IPv4-nya.
func getLocalSubnets() ([]subnetInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []subnetInterface
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
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			}

			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}

			mac := iface.HardwareAddr.String()
			network := ip.Mask(ipNet.Mask)

			result = append(result, subnetInterface{
				iface:   iface,
				ip:      ip,
				mac:     mac,
				ipNet:   ipNet,
				network: network,
			})
		}
	}
	return result, nil
}

// probeSubnets mengirimkan 1 paket ICMP echo ke host dalam subnet untuk memperbarui cache ARP.
func (d *Discovery) probeSubnets(ctx context.Context, subnets []subnetInterface) error {
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup

	for _, sub := range subnets {
		// Dapatkan daftar target IP (batasi mask untuk mencegah pemindaian terlalu luas di luar /24)
		targets := generateSubnetIPs(sub)

		for _, target := range targets {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			// Lewati IP pengguna sendiri
			if target.Equal(sub.ip) {
				continue
			}

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}

			wg.Add(1)
			go func(ip net.IP) {
				defer func() {
					<-sem
					wg.Done()
				}()

				pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()

				_ = pingSingleHost(pingCtx, ip)
			}(target)
		}
	}

	wg.Wait()
	return nil
}

// generateSubnetIPs menghasilkan daftar IP pada subnet (biasanya 1..254 untuk /24).
func generateSubnetIPs(sub subnetInterface) []net.IP {
	var ips []net.IP
	ones, bits := sub.ipNet.Mask.Size()
	// Jika subnet lebih besar dari /24 (misal /16 atau /8), batasi ke rentang /24 lokal IP pengguna
	// demi kepatuhan etis (hanya mengamati lingkungan terdekat).
	if ones < 24 && bits == 32 {
		baseIP := make(net.IP, 4)
		copy(baseIP, sub.ip.To4())
		baseIP[3] = 0 // Ubah menjadi X.X.X.0/24
		for i := 1; i < 255; i++ {
			ip := make(net.IP, 4)
			copy(ip, baseIP)
			ip[3] = byte(i)
			ips = append(ips, ip)
		}
		return ips
	}

	// Untuk subnet /24 atau lebih kecil
	baseIP := sub.ip.To4()
	if baseIP == nil {
		return nil
	}

	for i := 1; i < 255; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = byte(i)
		ips = append(ips, ip)
	}
	return ips
}

// pingSingleHost mengirim 1 paket ping ringan ke host.
func pingSingleHost(ctx context.Context, ip net.IP) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "500", ip.String())
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "500", ip.String())
	default: // Linux
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip.String())
	}
	return cmd.Run()
}

// arpItem menyimpan pasangan IP dan MAC.
type arpItem struct {
	ip  string
	mac string
}

// readARPTable membaca entri tabel ARP dari sistem operasi.
func readARPTable() ([]arpItem, error) {
	switch runtime.GOOS {
	case "linux":
		return readARPTableLinux()
	case "windows":
		return readARPTableWindows()
	case "darwin":
		return readARPTableDarwin()
	default:
		return readARPTableLinux()
	}
}

// readARPTableLinux membaca /proc/net/arp atau perintah ip neigh.
func readARPTableLinux() ([]arpItem, error) {
	// Cara 1: langsung baca file /proc/net/arp (sangat cepat & tanpa dependensi eksternal)
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		lines := strings.Split(string(data), "\n")
		var items []arpItem
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ip := fields[0]
				hwType := fields[1]
				mac := strings.ToUpper(fields[3])
				if hwType == "0x1" && mac != "00:00:00:00:00:00" && len(mac) == 17 {
					items = append(items, arpItem{ip: ip, mac: mac})
				}
			}
		}
		if len(items) > 0 {
			return items, nil
		}
	}

	// Cara 2: fallback ke perintah `ip neigh`
	if out, err := exec.Command("ip", "neigh").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		var items []arpItem
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				ip := fields[0]
				for i, f := range fields {
					if f == "lladdr" && i+1 < len(fields) {
						mac := strings.ToUpper(fields[i+1])
						if mac != "00:00:00:00:00:00" && len(mac) == 17 {
							items = append(items, arpItem{ip: ip, mac: mac})
						}
						break
					}
				}
			}
		}
		return items, nil
	}

	return nil, errors.New("tidak dapat membaca tabel ARP di Linux")
}

// readARPTableWindows membaca keluaran perintah `arp -a`.
func readARPTableWindows() ([]arpItem, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}
	return parseGenericARP(string(out))
}

// readARPTableDarwin membaca keluaran perintah `arp -an`.
func readARPTableDarwin() ([]arpItem, error) {
	out, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return nil, err
	}
	return parseGenericARP(string(out))
}

// parseGenericARP mengurai teks keluaran dari arp -a / arp -an.
func parseGenericARP(output string) ([]arpItem, error) {
	var items []arpItem
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		var foundIP, foundMAC string
		for _, f := range fields {
			cleanIP := strings.Trim(f, "()")
			if net.ParseIP(cleanIP) != nil && cleanIP != "255.255.255.255" {
				foundIP = cleanIP
			}
			cleanMAC := strings.ReplaceAll(f, "-", ":")
			if isMACString(cleanMAC) {
				foundMAC = strings.ToUpper(cleanMAC)
			}
		}
		if foundIP != "" && foundMAC != "" && foundMAC != "00:00:00:00:00:00" {
			items = append(items, arpItem{ip: foundIP, mac: foundMAC})
		}
	}
	return items, nil
}

// isMACString memvalidasi apakah string merupakan alamat MAC format 6 oktet.
func isMACString(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
	}
	return true
}

// isIgnoredMAC memeriksa apakah MAC adalah broadcast atau zero.
func isIgnoredMAC(mac string) bool {
	macUpper := strings.ToUpper(mac)
	return macUpper == "00:00:00:00:00:00" ||
		macUpper == "FF:FF:FF:FF:FF:FF" ||
		strings.HasPrefix(macUpper, "01:00:5E") ||
		strings.HasPrefix(macUpper, "33:33:")
}

// isIPInSubnets memeriksa apakah IP berada dalam daftar subnet yang diizinkan.
func isIPInSubnets(ip net.IP, subnets []subnetInterface) bool {
	for _, s := range subnets {
		if s.ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveHostname mencoba mencari nama host via reverse DNS dengan batas waktu 1 detik.
func resolveHostname(ctx context.Context, ipStr string) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ipStr)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

// LookupVendor memetakan prefix OUI alamat MAC ke nama pabrikan terkemuka.
func LookupVendor(mac string) string {
	mac = strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(mac)), "-", ":")
	if len(mac) < 8 {
		return ""
	}
	oui := mac[:8]

	switch oui {
	// Apple
	case "00:1A:7D", "00:25:00", "00:26:BB", "3C:D9:2B", "9C:D9:1D", "AC:DE:48", "F0:18:98":
		return "Apple"
	// Samsung
	case "00:25:90", "14:49:E0", "34:23:BA", "50:85:69", "54:92:BE", "88:32:9B":
		return "Samsung"
	// Google
	case "3C:5A:B4", "54:60:09", "94:EB:CD", "F4:F5:DB":
		return "Google"
	// TP-Link
	case "00:26:B9", "50:D4:F7", "60:32:B1", "70:4F:57", "98:48:27", "C0:06:C3":
		return "TP-Link"
	// Xiaomi
	case "00:9E:C8", "28:6C:07", "7C:49:EB", "84:F3:EB", "F8:1A:5E":
		return "Xiaomi"
	// Intel
	case "00:05:69", "00:1B:21", "00:1F:33", "00:25:2C", "D0:73:D3":
		return "Intel"
	// Raspberry Pi
	case "B8:27:EB", "DC:A6:32", "E4:5F:01":
		return "Raspberry Pi"
	// Espressif (IoT ESP8266/ESP32)
	case "24:6F:28", "30:AE:A4", "84:0D:8E", "A4:CF:12", "C4:4F:33":
		return "Espressif (IoT)"
	// Cisco
	case "00:00:0C", "00:01:42", "A0:36:9F", "E4:AA:5D":
		return "Cisco"
	// MikroTik
	case "48:8F:5A", "64:D1:54", "78:9A:18", "B8:69:F4", "C4:AD:34":
		return "MikroTik"
	// Dell
	case "00:1E:52", "00:21:5B", "00:23:AE", "F0:4D:A2":
		return "Dell"
	// HP
	case "00:80:5F", "2C:41:38", "3C:D9:2B:AA", "AC:DE:4C":
		return "HP"
	// Huawei
	case "00:1E:10", "04:25:C5", "48:46:FB", "E8:CD:2D":
		return "Huawei"
	// Asus
	case "00:1F:C6", "04:D9:F5", "1C:87:2C", "E8:9A:37":
		return "ASUSTek"
	// Realtek
	case "00:E0:4C", "52:54:00":
		return "Realtek"
	// VMware
	case "00:0C:29", "00:50:56":
		return "VMware"
	}

	return ""
}
