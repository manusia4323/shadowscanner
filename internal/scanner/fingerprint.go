// Package fingerprint guesses device type from multiple weak signals:
// MAC OUI lookup, hostname patterns, open ports, and vendor keywords.
// Each signal contributes 0.2 to confidence, capped at 1.0.
package fingerprint

import (
	"strings"
)

// Fingerprint holds the result of guessing device type.
type Fingerprint struct {
	DeviceType string   // e.g., "Router", "Ponsel", "Laptop", "Printer", "TV", "Kamera IP", "IoT", "Perangkat tidak dikenal"
	Vendor     string   // Vendor name from OUI lookup
	Confidence float64  // Confidence score 0.0 - 1.0
	Signals    []string // Human-readable reasons for the guess
}

// Guess infers device type from weak signals. Each matched signal adds 0.2
// to confidence, capped at 1.0. If no signal matches, returns
// "Perangkat tidak dikenal" with confidence 0.0.
func Guess(dev Device, ports []PortResult) Fingerprint {
	var signals []string
	confidence := 0.0

	// 1. MAC OUI lookup provides vendor info
	vendor := dev.Vendor
	fp := Fingerprint{
		Vendor: vendor,
	}

	// Build lowercase hostname for pattern matching
	hostnameLower := strings.ToLower(dev.Hostname)

	// 2. Hostname patterns
	hostnameType := guessFromHostname(hostnameLower)
	if hostnameType != "" {
		signals = append(signals, "Hostname: "+dev.Hostname)
		confidence += 0.2
		fp.DeviceType = hostnameType
	}

	// 3. Open ports signal
	portType, portMatched := guessFromPorts(ports)
	if portMatched {
		signals = append(signals, guessFromPortsDescription(ports))
		confidence += 0.2
		if fp.DeviceType == "" {
			fp.DeviceType = portType
		}
	}

	// 4. Vendor name keywords (from OUI)
	vendorType, vendorMatched := guessFromVendor(strings.ToLower(vendor))
	if vendorMatched {
		signals = append(signals, "Vendor: "+vendor)
		confidence += 0.2
		if fp.DeviceType == "" {
			fp.DeviceType = vendorType
		}
	}

	// Final type determination
	if fp.DeviceType == "" && confidence == 0 {
		fp.DeviceType = "Perangkat tidak dikenal"
	}
	// If only one type determined, use that. If multiple, prioritize hostname
	// then ports then vendor. We'll pick the first non-empty type.
	if fp.DeviceType == "" {
		// Check if any type was determined by signals but confidence wasn't set
		// This shouldn't happen, but just in case:
		fp.DeviceType = "Perangkat tidak dikenal"
	}

	// Cap confidence at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	fp.Confidence = confidence
	fp.Signals = signals

	return fp
}

// guessFromHostname matches hostname substring patterns against known device types.
// Returns device type or empty string if no match.
func guessFromHostname(hostname string) string {
	if hostname == "" {
		return ""
	}

	// Mobile devices
	if contains(hostname, "iphone", "ipad", "android", "pixel", "samsung", "xiaomi") {
		return "Ponsel"
	}

	// Laptops
	if contains(hostname, "desktop-", "laptop-", "macbook", "thinkpad") {
		return "Laptop"
	}

	// IoT devices
	if contains(hostname, "raspberrypi", "esp-", "tasmota", "shelly") {
		return "IoT"
	}

	// Printers
	if contains(hostname, "printer", "hp ", "canon", "epson", "brother") {
		return "Printer"
	}

	// Smart TV / streaming
	if contains(hostname, "tv", "chromecast", "roku", "firestick") {
		return "TV"
	}

	// IP Cameras
	if contains(hostname, "camera", "ipcam", "hikvision", "dahua") {
		return "Kamera IP"
	}

	// Routers / gateways
	if contains(hostname, "router", "gateway", "openwrt", "mikrotik", "tplink") {
		return "Router"
	}

	return ""
}

// guessFromPorts checks open ports against known patterns to guess device type.
// Returns device type and true if a port pattern matched.
func guessFromPorts(ports []PortResult) (string, bool) {
	hasPort := func(p int) bool {
		for _, port := range ports {
			if port.Open && port.Port == p {
				return true
			}
		}
		return false
	}

	// Check patterns in priority order
	// 3389 open -> Windows Laptop
	if hasPort(3389) {
		return "Laptop", true
	}

	// 22 + 80/443 open -> Linux/embedded: IoT or Router
	if hasPort(22) && (hasPort(80) || hasPort(443)) {
		return "IoT", true
	}

	// 445 + 139 open -> Windows file sharing -> Laptop
	if hasPort(445) && hasPort(139) {
		return "Laptop", true
	}

	// 9100 open -> Printer (rare, kept for v2)
	if hasPort(9100) {
		return "Printer", true
	}

	return "", false
}

// guessFromPortsDescription returns a human-readable string describing
// which ports were detected as significant.
func guessFromPortsDescription(ports []PortResult) string {
	var openPorts []string
	for _, p := range ports {
		if p.Open {
			openPorts = append(openPorts, strconv.Itoa(p.Port))
		}
	}
	if len(openPorts) == 0 {
		return "No significant ports open"
	}
	return "Open ports: " + strings.Join(openPorts, ", ")
}

// guessFromVendor checks vendor name keywords against known patterns.
// Returns device type and true if a vendor pattern matched.
func guessFromVendor(vendorLower string) (string, bool) {
	if vendorLower == "" {
		return "", false
	}

	// Apple -> Ponsel or Laptop (ambiguous, but default to Laptop)
	if strings.Contains(vendorLower, "apple") {
		return "Laptop", true
	}

	// Samsung -> Ponsel
	if strings.Contains(vendorLower, "samsung") {
		return "Ponsel", true
	}

	// Networking vendors -> Router
	if strings.Contains(vendorLower, "tp-link") ||
		strings.Contains(vendorLower, "mikrotik") ||
		strings.Contains(vendorLower, "ubiquiti") ||
		strings.Contains(vendorLower, "cisco") ||
		strings.Contains(vendorLower, "netgear") {
		return "Router", true
	}

	// Camera vendors -> Kamera IP
	if strings.Contains(vendorLower, "hikvision") ||
		strings.Contains(vendorLower, "dahua") {
		return "Kamera IP", true
	}

	// Printer vendors
	if strings.Contains(vendorLower, "hp ") ||
		strings.Contains(vendorLower, "canon") ||
		strings.Contains(vendorLower, "epson") ||
		strings.Contains(vendorLower, "brother") {
		return "Printer", true
	}

	return "", false
}

// contains checks if any substring exists in the target string.
func contains(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
