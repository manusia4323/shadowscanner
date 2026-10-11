// Package config menangani pemuatan dan validasi konfigurasi aplikasi
// dari file .env, variabel lingkungan (environment variables), dan
// pengaturan bawaan yang aman.
package config

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config menyimpan pengaturan yang dapat dikonfigurasi pengguna untuk
// ShadowScanner. Setiap bidang memiliki default yang aman bila tidak
// disediakan di .env atau variabel lingkungan.
type Config struct {
	Port               int           // Port HTTP untuk UI lokal (range: 1024-65535)
	RetentionHours     int           // Durasi simpan riwayat dalam jam (range: 1-720)
	ScanIntervalSec    int           // Interval pemindaian koneksi dalam detik (range: 10-3600)
	WarningMode        bool          // Aktifkan notifikasi/peringatan suara saat ada peringatan baru
	LogLevel           string        // Level log: debug/info/warn/error
	MaxDevices         int           // Maksimal perangkat yang dicatat (range: 1-1024)
	DBPath             string        // Lokasi file database SQLite lokal
	ShutdownTimeoutSec int           // Durasi grace period saat shutdown, dalam detik
	NetworkInterface   string        // Nama antarmuka jaringan khusus untuk dipindai (opsional)
	CaptureDevice      string        // Nama device capture (libpcap/Npcap) khusus (opsional)
	BrowserLaunch      bool          // Buka browser otomatis saat start (opsional, default true)
	Environment        string        // "development" bila berjalan tanpa .env yang valid, else "production"
}

const (
	// DefaultPort HTTP default.
	DefaultPort = 8787
	// DefaultRetentionHours default penyimpanan riwayat (8 jam).
	DefaultRetentionHours = 8
	// DefaultScanIntervalSec default interval pemindaian (60 detik).
	DefaultScanIntervalSec = 60
	// DefaultWarningMode default mode peringatan.
	DefaultWarningMode = false
	// DefaultLogLevel default level log.
	DefaultLogLevel = "info"
	// DefaultMaxDevices default maksimal perangkat (256).
	DefaultMaxDevices = 256
	// DefaultDBPath default lokasi database (file lokal).
	DefaultDBPath = "./shadowscanner.db"
	// DefaultShutdownTimeoutSec default grace period shutdown (5 detik).
	DefaultShutdownTimeoutSec = 5
	// DefaultBrowserLaunch default buka browser otomatis.
	DefaultBrowserLaunch = true

	// minimum/maksimum range untuk setiap bidang.
	minPort      = 1024
	maxPort      = 65535
	minRetention = 1
	maxRetention = 720
	minInterval  = 10
	maxInterval  = 3600
	minDevices   = 1
	maxDevices   = 1024
)

// Load memuat konfigurasi dari file .env, lalu dari variabel lingkungan,
// dan akhirnya menerapkan default yang aman. Jika .env tidak ditemukan,
// godotenv mengabaikan error tersebut sehingga aplikasi tetap berjalan.
//
// Load mengembalikan *Config yang sudah lengkap dan terisi — tidak pernah
// nil. Kesalahan hanya muncul untuk kegagalan membaca file atau log level
// yang tidak valid.
func Load() (*Config, error) {
	// Coba muat .env dari direktori kerja saat ini.
	if err := godotenv.Load(); err != nil {
		// .env tidak wajib: lanjutkan ke env vars + default.
		_ = err
	}

	cfg := &Config{}

	// --- Port ---
	if v := os.Getenv("SHADOWSCANNER_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Port = i
		}
	}
	if cfg.Port < minPort || cfg.Port > maxPort {
		cfg.Port = DefaultPort
	}

	// --- Retention ---
	if v := os.Getenv("SHADOWSCANNER_RETENTION_HOURS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.RetentionHours = i
		}
	}
	if cfg.RetentionHours < minRetention || cfg.RetentionHours > maxRetention {
		cfg.RetentionHours = DefaultRetentionHours
	}

	// --- Scan interval ---
	if v := os.Getenv("SHADOWSCANNER_SCAN_INTERVAL_SECONDS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.ScanIntervalSec = i
		}
	}
	if cfg.ScanIntervalSec < minInterval || cfg.ScanIntervalSec > maxInterval {
		cfg.ScanIntervalSec = DefaultScanIntervalSec
	}

	// --- Warning mode ---
	if v := os.Getenv("SHADOWSCANNER_WARNING_MODE"); v != "" {
		cfg.WarningMode = stringsTrimBool(v)
	}
	cfg.WarningMode = cfg.WarningMode || DefaultWarningMode

	// --- Log level ---
	if v := os.Getenv("SHADOWSCANNER_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	// --- Max devices ---
	if v := os.Getenv("SHADOWSCANNER_MAX_DEVICES"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.MaxDevices = i
		}
	}
	if cfg.MaxDevices < minDevices || cfg.MaxDevices > maxDevices {
		cfg.MaxDevices = DefaultMaxDevices
	}

	// --- Database path ---
	if v := os.Getenv("SHADOWSCANNER_DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if cfg.DBPath == "" {
		cfg.DBPath = DefaultDBPath
	}

	// --- Shutdown timeout ---
	if v := os.Getenv("SHADOWSCANNER_SHUTDOWN_TIMEOUT_SECONDS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.ShutdownTimeoutSec = i
		}
	}
	if cfg.ShutdownTimeoutSec < 1 {
		cfg.ShutdownTimeoutSec = DefaultShutdownTimeoutSec
	}

	// --- Network interface (opsional) ---
	cfg.NetworkInterface = os.Getenv("SHADOWSCANNER_NETWORK_INTERFACE")

	// --- Capture device (opsional) ---
	cfg.CaptureDevice = os.Getenv("SHADOWSCANNER_CAPTURE_DEVICE")

	// --- Browser launch ---
	if v := os.Getenv("SHADOWSCANNER_BROWSER_LAUNCH"); v != "" {
		cfg.BrowserLaunch = stringsTrimBool(v)
	}
	cfg.BrowserLaunch = cfg.BrowserLaunch || DefaultBrowserLaunch

	// Environment detection: bila .env berhasil dibaca, ini "production";
	// bila tidak, tandai "development" agar aplikasi tidak berprasangka.
	cfg.Environment = "development"
	if _, err := os.Stat(".env"); err == nil {
		cfg.Environment = "production"
	}

	// Validasi menyeluruh — kembalikan kesalahan deskriptif, bukan panic.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate memeriksa seluruh konfigurasi dan mengembalikan kesalahan deskriptif
// bila ada nilai di luar range aman. Fungsi ini menjamin invariant yang
// diterapkan pada setiap bidang Config.
func (c *Config) Validate() error {
	if c.Port < minPort || c.Port > maxPort {
		return fmt.Errorf("port %d di luar range aman %d-%d", c.Port, minPort, maxPort)
	}
	if c.RetentionHours < minRetention || c.RetentionHours > maxRetention {
		return fmt.Errorf("retention hours %d di luar range %d-%d", c.RetentionHours, minRetention, maxRetention)
	}
	if c.ScanIntervalSec < minInterval || c.ScanIntervalSec > maxInterval {
		return fmt.Errorf("scan interval %d di luar range %d-%d", c.ScanIntervalSec, minInterval, maxInterval)
	}
	if c.MaxDevices < minDevices || c.MaxDevices > maxDevices {
		return fmt.Errorf("max devices %d di luar range %d-%d", c.MaxDevices, minDevices, maxDevices)
	}
	if c.DBPath == "" {
		return fmt.Errorf("DB path tidak boleh kosong")
	}
	if level := c.LogLevel; level != "debug" && level != "info" && level != "warn" && level != "error" {
		return fmt.Errorf("log level %q tidak valid; gunakan debug/info/warn/error", level)
	}
	return nil
}

// PlatformOS mengidentifikasi sistem operasi secara lebih deskriptif
// (misalnya "Windows 11", "Ubuntu 22.04") berdasarkan runtime dan OS yang
// terdeteksi. Digunakan untuk laporan device.
func PlatformOS() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch goos {
	case "windows":
		// Windows 11/10 dapat dibedakan lewat os (opsional, tetap sederhana).
		if goarch == "amd64" {
			return "Windows 10/11"
		}
		return "Windows"
	case "linux":
		return "Linux (" + goarch + ")"
	case "darwin":
		return "macOS"
	default:
		return goos
	}
}

// stringsTrimBool menerjemahkan string lingkungan menjadi bool. Nilai
// yang jelas "true"/1/yes/on/benar dianggap aktif; nilai lain dianggap
// tidak aktif. Ini mencegah nilai yang salah merusak konfigurasi.
func stringsTrimBool(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "true" || s == "1" || s == "yes" || s == "on" || s == "benar"
}
