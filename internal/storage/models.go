// Package storage menyediakan lapisan data SQLite dengan operasi CRUD
// sederhana, tanpa ORM. File models.go mendefinisikan struktur Go yang
// secara langsung mencerminkan tabel SQLite dengan tag basis data.
package storage

import (
	"time"
)

// Device merekam satu perangkat yang terdeteksi di jaringan lokal.
// ID adalah kunci utama; MAC adalah identitas unik perangkat.
type Device struct {
	ID                  int64     // Kunci utama SQLite (auto-increment)
	MAC                 string    // Alamat MAC dalam format XX:XX:XX:XX:XX:XX
	IP                  string    // Alamat IPv4 (mis. 192.168.1.42)
	Hostname            string    // Nama host dari DNS/mDNS (mis. "laptop-ani")
	Vendor              string    // Nama vendor dari OUI (mis. "Apple", "Samsung")
	DeviceType          string    // Tebakan tipe: "Router", "Ponsel", "Laptop", dst.
	FirstSeen           time.Time // Waktu pertama kali perangkat dilihat
	LastSeen            time.Time // Waktu terakhir kali perangkat dilihat
	Confidence          float64   // Keyakinan identitas (0.0-1.0)
	DistanceEstimate    float64   // Jarak estimasi dari pengguna dalam meter
	DistanceConfidence  string    // Tingkat keyakinan jarak: "rendah", "sedang", "tinggi"
}

// Alert merekam satu peringatan keamanan yang dihasilkan dari aktivitas
// mencurigakan dalam jaringan (ARP spoofing, rogue DHCP, dst.).
type Alert struct {
	ID          int64     // Kunci utama SQLite (auto-increment)
	Timestamp   time.Time // Waktu peringatan dibuat
	Severity    string    // Tingkat keparahan: "aman", "perhatian", "bahaya"
	Category    string    // Jenis peringatan: "arp", "mac", "dhcp", "dns", "gateway", "inject"
	Title       string    // Judul singkat dalam bahasa Indonesia (maks. 8 kata)
	Explanation string    // Penjelasan 2-3 kalimat dalam bahasa Indonesia tanpa jargon
	Action      string    // Langkah konkret 1-3 dalam bahasa Indonesia untuk pengguna
	Technical   string    // Detail teknis (IP, MAC, port) untuk pengguna lanjutan
	DeviceMAC   string    // MAC perangkat terkait (jika ada)
	Acknowledged bool      // Tandai sudah dibaca oleh pengguna
}

// Connection merekam satu sambungan jaringan aktif yang dimiliki oleh
// proses di mesin pengguna (hanya untuk koneksi lokal, bukan paket jaringan).
type Connection struct {
	ID          int64     // Kunci utama SQLite (auto-increment)
	Timestamp   time.Time // Waktu sambungan pertama kali terlihat
	Direction   string    // Arah: "masuk" (server) atau "keluar" (klien)
	LocalIP     string    // Alamat IP lokal mesin pengguna
	LocalPort   int       // Port lokal mesin pengguna
	RemoteIP    string    // Alamat IP jarak jauh (bisa lokal atau publik)
	RemotePort  int       // Port jarak jauh
	Protocol    string    // Protokol: "TCP" atau "UDP"
	ProcessName string    // Nama proses yang membuka sambungan
	ProcessPID  int       // ID proses yang membuka sambungan
	State       string    // Status TCP/UDP: "ESTABLISHED", "LISTEN", "CLOSE_WAIT", dst.
}

// Scan merekam satu jalur pemindaian jaringan lengkap.
// Digunakan untuk melacak statistik dalam periode waktu.
type Scan struct {
	ID           int64     // Kunci utama SQLite (auto-increment)
	StartedAt    time.Time // Waktu pemindaian dimulai
	FinishedAt   time.Time // Waktu pemindaian selesai
	DeviceCount  int       // Jumlah unik perangkat yang terdeteksi selama pemindaian
	AlertCount   int       // Jumlah peringatan baru yang dihasilkan selama pemindaian
}

// Setting adalah pasangan nilai kunci sederhana untuk menyimpan
// preferensi pengguna yang tetap di basis data (mis. durasi retention).
type Setting struct {
	Key   string // Nama pengaturan (harus unik)
	Value string // Nilai pengaturan sebagai string
}
