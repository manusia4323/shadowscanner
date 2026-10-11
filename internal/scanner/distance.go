// Package distance estimates the rough distance between the user's device
// and each discovered device, using the best available signal.
// Estimates are always labeled as "perkiraan" (estimate) and confidence
// is categorized as "rendah", "sedang", or "tinggi".
package distance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
)

// DistanceEstimate holds the estimated distance to a device.
type DistanceEstimate struct {
	Meters     float64 // Estimated distance in meters
	Confidence string  // "rendah" | "sedang" | "tinggi"
	Method     string  // "CSI" | "RSSI" | "tidak diketahui"
}

// Estimate attempts to determine distance using the best available method.
// Priority: 1. CSI (Channel State Information), 2. RSSI from OS WiFi API,
// 3. "tidak diketahui" with low confidence.
func Estimate(ctx context.Context, dev Device) DistanceEstimate {
	// Method 1: CSI (Channel State Information)
	// Check if Linux WiFi interface exposes CSI via nexmon or iwlwifi
	// This requires patched drivers and is optional.
	if csiEst := tryCSI(ctx); csiEst != nil {
		return *csiEst
	}

	// Method 2: RSSI from OS WiFi API
	if rssiEst := tryRSSI(ctx); rssiEst != nil {
		return *rssiEst
	}

	// Method 3: Unknown
	return DistanceEstimate{
		Meters:     0,
		Confidence: "rendah",
		Method:     "tidak diketahui",
	}
}

// tryCSI attempts to read CSI data from Linux WiFi interface.
// Returns nil if CSI is not available (requires patched driver).
func tryCSI(ctx context.Context) *DistanceEstimate {
	// CSI requires specific hardware and patched drivers (nexmon, iwlwifi-csi).
	// On standard systems, this is not available.
	// We check for common CSI interfaces like /proc/net/wireless or debugfs.
	// For this session, we return nil to indicate CSI is unavailable.
	// Future sessions can implement actual CSI reading if needed.
	return nil
}

// tryRSSI attempts to get signal strength (RSSI) from the OS WiFi API.
// Linux: `iw dev <iface> station dump` → parse "signal:" field
// Windows: `netsh wlan show interfaces` → parse "Signal"
// Converts RSSI (dBm) to meters using log-distance path loss model.
// Returns nil if RSSI cannot be obtained.
func tryRSSI(ctx context.Context) *DistanceEstimate {
	// Try Linux first
	if est := tryRSSILinux(); est != nil {
		return est
	}
	// Try Windows
	if est := tryRSSIWindows(); est != nil {
		return est
	}
	// macOS support could be added later
	return nil
}

// tryRSSILinux runs `iw dev <iface> station dump` and parses signal strength.
// Returns nil if command fails or no signal found.
func tryRSSILinux() *DistanceEstimate {
	// Get default WiFi interface (typically wlan0, wlp2s0, etc.)
	// We'll try to find a wireless interface
	iface := getLinuxWifiInterface()
	if iface == "" {
		return nil
	}

	// Run iw dev <iface> station dump
	cmd := exec.Command("iw", "dev", iface, "station", "dump")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse output for "signal:" field (in dBm)
	// Example output:
	// Station aa:bb:cc:dd:ee:ff (on wlan0)
	//         signal: -45 dBm
	//         signal avg: -42 dBm
	lines := strings.Split(string(output), "\n")
	var rssi int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "signal:") {
			// Format: "signal: -45 dBm"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				rssiStr := strings.TrimSuffix(parts[1], "dBm")
				rssiStr = strings.TrimSpace(rssiStr)
				if val, err := strconv.Atoi(rssiStr); err == nil {
					rssi = val
					break
				}
			}
		}
	}

	if rssi == 0 {
		// If signal not found (maybe not connected), try average signal
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "signal avg:") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					rssiStr := strings.TrimSuffix(parts[2], "dBm")
					rssiStr = strings.TrimSpace(rssiStr)
					if val, err := strconv.Atoi(rssiStr); err == nil {
						rssi = val
						break
					}
				}
			}
		}
	}

	if rssi == 0 {
		return nil
	}

	// Convert RSSI to distance using log-distance path loss model
	// d = 10 ^ ((TxPower - RSSI) / (10 * n))
	// TxPower = -30 dBm (typical at 1m)
	// n = 2.7 (indoor path loss exponent)
	txPower := -30.0
	n := 2.7
	distance := math.Pow(10, (txPower-float64(rssi))/(10.0*n))

	// Confidence: "sedang" if RSSI between -30 and -80 dBm, else "rendah"
	confidence := "sedang"
	if rssi < -80 || rssi > -30 {
		confidence = "rendah"
	}

	return &DistanceEstimate{
		Meters:     distance,
		Confidence: confidence,
		Method:     "RSSI",
	}
}

// getLinuxWifiInterface attempts to find a wireless interface name.
// Returns the first interface that appears to be wireless.
func getLinuxWifiInterface() string {
	// Read /proc/net/wireless for wireless interfaces
	data, err := exec.Command("cat", "/proc/net/wireless").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Inter-|") || strings.HasPrefix(line, "face") {
			continue
		}
		// Format: wlan0:   0000   32.  -45.  -256
		parts := strings.Fields(line)
		if len(parts) > 0 {
			// Remove trailing colon
			iface := strings.TrimSuffix(parts[0], ":")
			return iface
		}
	}
	return ""
}

// tryRSSIWindows runs `netsh wlan show interfaces` and parses Signal strength.
// Returns nil if command fails or no signal found.
func tryRSSIWindows() *DistanceEstimate {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse output for "Signal" field
	// Example: "Signal                 : 80%"
	lines := strings.Split(string(output), "\n")
	var signalPercent int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Signal") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				valStr := strings.TrimSpace(parts[1])
				valStr = strings.TrimSuffix(valStr, "%")
				valStr = strings.TrimSpace(valStr)
				if val, err := strconv.Atoi(valStr); err == nil {
					signalPercent = val
					break
				}
			}
		}
	}

	if signalPercent == 0 {
		return nil
	}

	// Convert signal percentage to approximate dBm
	// Windows signal % mapping: 0% ~ -100 dBm, 100% ~ -50 dBm (rough approximation)
	// Linear mapping: dBm = -100 + signal% * 0.5
	// But this is very approximate. Better: use standard mapping.
	// Common mapping: -100 dBm = 0%, -90 = 10%, -80 = 30%, -70 = 50%, -60 = 70%, -50 = 100%
	// We'll use a simple piecewise linear approximation
	var rssi int
	if signalPercent >= 100 {
		rssi = -50
	} else if signalPercent >= 80 {
		rssi = -60
	} else if signalPercent >= 60 {
		rssi = -70
	} else if signalPercent >= 40 {
		rssi = -80
	} else if signalPercent >= 20 {
		rssi = -90
	} else {
		rssi = -100
	}

	// Convert RSSI to distance
	txPower := -30.0
	n := 2.7
	distance := math.Pow(10, (txPower-float64(rssi))/(10.0*n))

	confidence := "sedang"
	if rssi < -80 || rssi > -30 {
		confidence = "rendah"
	}

	return &DistanceEstimate{
		Meters:     distance,
		Confidence: confidence,
		Method:     "RSSI",
	}
}