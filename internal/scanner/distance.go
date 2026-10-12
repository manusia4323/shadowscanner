// Package scanner menyediakan fungsi pemindaian defensif untuk jaringan lokal.
package scanner

import (
	"context"
	"math"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// DistanceEstimate merekam perkiraan jarak fisik antara mesin pengguna dan perangkat lain.
type DistanceEstimate struct {
	Meters     float64 // Perkiraan jarak dalam satuan meter
	Confidence string  // Tingkat keyakinan: "rendah" | "sedang" | "tinggi"
	Method     string  // Metode yang digunakan: "CSI" | "RSSI" | "tidak diketahui"
}

// Estimate memperkirakan jarak kasar dari pengguna ke perangkat target secara read-only.
// Selalu diberi label perkiraan dan tidak pernah mengklaim akurasi mutlak.
func Estimate(ctx context.Context, dev Device) DistanceEstimate {
	select {
	case <-ctx.Done():
		return DistanceEstimate{
			Meters:     0,
			Confidence: "rendah",
			Method:     "tidak diketahui",
		}
	default:
	}

	// 1. Prioritas 1: CSI (Channel State Information) jika driver WiFi mendukung.
	if csi, ok := tryEstimateCSI(ctx, dev); ok {
		return csi
	}

	// 2. Prioritas 2: RSSI (Received Signal Strength Indicator) dari API nirkabel OS.
	if rssi, ok := tryEstimateRSSI(ctx, dev); ok {
		return rssi
	}

	// 3. Fallback jika tidak tersedia sinyal radio nirkabel.
	return DistanceEstimate{
		Meters:     0,
		Confidence: "rendah",
		Method:     "tidak diketahui",
	}
}

// tryEstimateCSI memeriksa ketersediaan data Channel State Information (membutuhkan driver nexmon/iwlwifi khusus).
func tryEstimateCSI(ctx context.Context, dev Device) (DistanceEstimate, bool) {
	// Pada sistem operasi standar tanpa driver modifikasi, CSI tidak tersedia.
	// Dipertahankan sebagai placeholder arsitektural untuk Session/v2.
	return DistanceEstimate{}, false
}

// tryEstimateRSSI membaca kekuatan sinyal WiFi dari perintah sistem operasi secara read-only.
func tryEstimateRSSI(ctx context.Context, dev Device) (DistanceEstimate, bool) {
	switch runtime.GOOS {
	case "linux":
		return estimateRSSILinux(ctx, dev.MAC)
	case "windows":
		return estimateRSSIWindows(ctx)
	default:
		return DistanceEstimate{}, false
	}
}

// estimateRSSILinux membaca `iw dev <iface> station dump` dan mengurai nilai "signal:".
func estimateRSSILinux(ctx context.Context, targetMAC string) (DistanceEstimate, bool) {
	out, err := exec.CommandContext(ctx, "iw", "dev").Output()
	if err != nil {
		return DistanceEstimate{}, false
	}

	// Cari antarmuka nirkabel pertama dari keluaran `iw dev`
	var iface string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Interface ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				iface = parts[1]
				break
			}
		}
	}

	if iface == "" {
		return DistanceEstimate{}, false
	}

	// Eksekusi `iw dev <iface> station dump`
	dumpOut, err := exec.CommandContext(ctx, "iw", "dev", iface, "station", "dump").Output()
	if err != nil {
		return DistanceEstimate{}, false
	}

	dumpLines := strings.Split(string(dumpOut), "\n")
	var currentStation string
	for _, l := range dumpLines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "Station ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentStation = strings.ToUpper(parts[1])
			}
		} else if strings.HasPrefix(trimmed, "signal:") {
			// Jika station cocok dengan target MAC atau jika targetMAC kosong ambil station pertama
			if targetMAC == "" || strings.EqualFold(currentStation, targetMAC) {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					valStr := strings.TrimSuffix(fields[1], "dBm")
					val, convErr := strconv.Atoi(strings.TrimSpace(valStr))
					if convErr == nil && val < 0 {
						return calculateLogDistance(float64(val), "RSSI"), true
					}
				}
			}
		}
	}

	return DistanceEstimate{}, false
}

// estimateRSSIWindows membaca persentase sinyal dari `netsh wlan show interfaces`.
func estimateRSSIWindows(ctx context.Context) (DistanceEstimate, bool) {
	out, err := exec.CommandContext(ctx, "netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return DistanceEstimate{}, false
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Signal") && strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				valStr := strings.TrimSpace(strings.ReplaceAll(parts[1], "%", ""))
				pct, err := strconv.Atoi(valStr)
				if err == nil && pct > 0 {
					// Konversi perkiraan persentase ke dBm: 100% -> -50 dBm, 0% -> -100 dBm
					rssi := -100.0 + (float64(pct) * 0.5)
					return calculateLogDistance(rssi, "RSSI"), true
				}
			}
		}
	}
	return DistanceEstimate{}, false
}

// calculateLogDistance mengonversi nilai RSSI (dBm) ke meter menggunakan log-distance path loss model:
// d = 10 ^ ((TxPower - RSSI) / (10 * n))
// dengan TxPower = -30 dBm dan n = 2.7 (lingkungan dalam ruangan).
func calculateLogDistance(rssi float64, method string) DistanceEstimate {
	txPower := -30.0
	n := 2.7

	exponent := (txPower - rssi) / (10.0 * n)
	meters := math.Pow(10, exponent)
	meters = math.Round(meters*10) / 10 // bulatkan 1 desimal

	confidence := "sedang"
	if rssi < -80 || rssi > -30 {
		confidence = "rendah"
	}

	return DistanceEstimate{
		Meters:     meters,
		Confidence: confidence,
		Method:     method,
	}
}
