// Package scanner menyediakan fungsi pemindaian defensif untuk jaringan lokal.
package scanner

import (
	"fmt"
	"strings"
)

// Fingerprint merekam hasil tebakan tipe perangkat berdasarkan kombinasi sinyal-sinyal lemah.
type Fingerprint struct {
	DeviceType string   // "Router", "Ponsel", "Laptop", "Printer", "TV", "Kamera IP", "IoT", atau "Perangkat tidak dikenal"
	Vendor     string   // Nama pabrikan
	Confidence float64  // Nilai keyakinan 0.0 - 1.0
	Signals    []string // Alasan dan bukti sinyal dalam bahasa yang mudah dipahami
}

// Guess menebak tipe perangkat berdasarkan alamat MAC OUI, nama host, dan port terbuka.
// Setiap sinyal yang cocok menyumbang nilai 0.2 pada skor keyakinan (maksimum 1.0).
func Guess(dev Device, ports []PortResult) Fingerprint {
	var signals []string
	confidence := 0.0
	guessedType := ""

	vendor := dev.Vendor
	if vendor == "" {
		vendor = LookupVendor(dev.MAC)
	}

	// 1. Sinyal dari MAC OUI Vendor
	if vendor != "" {
		signals = append(signals, fmt.Sprintf("Pabrikan dikenali: %s", vendor))
		confidence += 0.2

		vLower := strings.ToLower(vendor)
		if strings.Contains(vLower, "tp-link") ||
			strings.Contains(vLower, "mikrotik") ||
			strings.Contains(vLower, "ubiquiti") ||
			strings.Contains(vLower, "cisco") ||
			strings.Contains(vLower, "netgear") {
			guessedType = "Router"
		} else if strings.Contains(vLower, "hikvision") || strings.Contains(vLower, "dahua") {
			guessedType = "Kamera IP"
		} else if strings.Contains(vLower, "espressif") || strings.Contains(vLower, "raspberry") {
			guessedType = "IoT"
		} else if strings.Contains(vLower, "samsung") {
			guessedType = "Ponsel"
		} else if strings.Contains(vLower, "apple") {
			guessedType = "Laptop" // Apple dapat berupa ponsel atau laptop, disesuaikan oleh hostname nanti
		}
	}

	// 2. Sinyal dari pola Hostname
	if dev.Hostname != "" {
		hLower := strings.ToLower(dev.Hostname)
		hType := matchHostnamePattern(hLower)
		if hType != "" {
			signals = append(signals, fmt.Sprintf("Nama host cocok (%s): %s", hType, dev.Hostname))
			confidence += 0.2
			guessedType = hType
		}
	}

	// 3. Sinyal dari Port Terbuka
	portType, matchedPorts := matchPortSignals(ports)
	if portType != "" {
		signals = append(signals, fmt.Sprintf("Port terbuka khas (%s): port %v", portType, matchedPorts))
		confidence += 0.2
		// Jika belum ada tebakan atau tebakan sebelumnya adalah generic, gunakan portType
		if guessedType == "" || guessedType == "Perangkat tidak dikenal" {
			guessedType = portType
		}
	}

	// 4. Batasi skor confidence maksimal 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	if guessedType == "" || confidence == 0 {
		guessedType = "Perangkat tidak dikenal"
		confidence = 0.0
	}

	return Fingerprint{
		DeviceType: guessedType,
		Vendor:     vendor,
		Confidence: confidence,
		Signals:    signals,
	}
}

// matchHostnamePattern mencocokkan substring nama host dengan tipe perangkat.
func matchHostnamePattern(h string) string {
	switch {
	case containsAny(h, "iphone", "ipad", "android", "pixel", "samsung", "xiaomi", "redmi", "oppo", "vivo"):
		return "Ponsel"
	case containsAny(h, "desktop-", "laptop-", "macbook", "thinkpad", "pc-", "notebook"):
		return "Laptop"
	case containsAny(h, "raspberrypi", "esp-", "esp32", "tasmota", "shelly", "arduino"):
		return "IoT"
	case containsAny(h, "printer", "hp-", "canon", "epson", "brother"):
		return "Printer"
	case containsAny(h, "tv", "chromecast", "roku", "firestick", "smarttv", "bravia"):
		return "TV"
	case containsAny(h, "camera", "ipcam", "hikvision", "dahua", "cctv", "cam-"):
		return "Kamera IP"
	case containsAny(h, "router", "gateway", "openwrt", "mikrotik", "tplink", "accesspoint", "ap-"):
		return "Router"
	default:
		return ""
	}
}

// matchPortSignals memeriksa port terbuka yang menjadi indikator kuat jenis perangkat.
func matchPortSignals(ports []PortResult) (string, []int) {
	openMap := make(map[int]bool)
	for _, p := range ports {
		if p.Open {
			openMap[p.Port] = true
		}
	}

	// 3389 open -> Windows Remote Desktop -> Laptop / PC
	if openMap[3389] {
		return "Laptop", []int{3389}
	}

	// 445 + 139 open -> SMB File Sharing -> Laptop / PC
	if openMap[445] && openMap[139] {
		return "Laptop", []int{139, 445}
	}

	// 22 open + 80 atau 443 open -> Embedded Linux Router / IoT
	if openMap[22] && (openMap[80] || openMap[443]) {
		var matched []int
		matched = append(matched, 22)
		if openMap[80] {
			matched = append(matched, 80)
		}
		if openMap[443] {
			matched = append(matched, 443)
		}
		return "Router", matched
	}

	// 80 atau 443 terbuka saja -> Web interface router atau printer
	if openMap[80] || openMap[443] {
		var matched []int
		if openMap[80] {
			matched = append(matched, 80)
		}
		if openMap[443] {
			matched = append(matched, 443)
		}
		return "Router", matched
	}

	return "", nil
}

// containsAny memeriksa apakah ada substring yang cocok.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
