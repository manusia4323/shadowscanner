// Package alert menyediakan mesin deteksi dan pembuatan peringatan keamanan
// dalam bahasa Indonesia yang mudah dipahami oleh pengguna non-teknis.
package alert

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"shadowscanner/internal/storage"
)

// Severity mendefinisikan tingkat keparahan suatu peringatan.
type Severity string

const (
	// SeveritySafe menandakan kondisi jaringan aman dan normal.
	SeveritySafe Severity = "aman"
	// SeverityAttention menandakan adanya aktivitas yang perlu diperhatikan.
	SeverityAttention Severity = "perhatian"
	// SeverityDanger menandakan ancaman aktif yang membutuhkan tindakan segera.
	SeverityDanger Severity = "bahaya"
)

// Alert merekam satu insiden keamanan yang dapat ditampilkan kepada pengguna.
type Alert struct {
	ID          int64     // ID unik peringatan
	Timestamp   time.Time // Waktu terjadinya insiden
	Severity    Severity  // Tingkat keparahan: "aman" | "perhatian" | "bahaya"
	Category    string    // Kategori: "arp" | "mac" | "dhcp" | "dns" | "gateway" | "inject"
	Title       string    // Judul singkat (maks 8 kata) dalam bahasa Indonesia
	Explanation string    // Penjelasan 2-3 kalimat tanpa jargon teknis
	Action      string    // Langkah tindakan konkret 1-3 langkah
	Technical   string    // Detail teknis (IP, MAC, dsb) untuk investigasi lebih lanjut
	DeviceMAC   string    // Alamat MAC perangkat terkait jika ada
}

// Broadcaster mendefinisikan kontrak untuk menyiarkan peringatan ke SSE hub.
type Broadcaster interface {
	Broadcast(event string, data any)
}

// Engine mengelola pembuatan, penyimpanan, dan pengakuan peringatan keamanan.
type Engine struct {
	db          *storage.DB
	mu          sync.RWMutex
	broadcaster Broadcaster
}

// NewEngine menciptakan instance Engine baru dengan basis data yang diberikan.
func NewEngine(db *storage.DB) *Engine {
	return &Engine{
		db: db,
	}
}

// SetBroadcaster menetapkan broadcaster untuk menyiarkan event SSE saat alert baru dibuat.
func (e *Engine) SetBroadcaster(b Broadcaster) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.broadcaster = b
}

// Raise memvalidasi peringatan, menetapkan waktu jika belum ada, menyimpannya
// ke tabel basis data, dan menyiarkannya ke klien melalui SSE hub.
func (e *Engine) Raise(a Alert) error {
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}

	dbAlert := &storage.Alert{
		Timestamp:    a.Timestamp,
		Severity:     string(a.Severity),
		Category:     a.Category,
		Title:        a.Title,
		Explanation:  a.Explanation,
		Action:       a.Action,
		Technical:    a.Technical,
		DeviceMAC:    a.DeviceMAC,
		Acknowledged: false,
	}

	id, err := e.db.InsertAlert(dbAlert)
	if err != nil {
		return fmt.Errorf("gagal menyimpan peringatan: %w", err)
	}
	a.ID = id

	e.mu.RLock()
	broadcaster := e.broadcaster
	e.mu.RUnlock()

	if broadcaster != nil {
		broadcaster.Broadcast("alert", a)
	}

	slog.Warn("peringatan keamanan terdeteksi",
		"id", a.ID,
		"severity", a.Severity,
		"category", a.Category,
		"title", a.Title,
	)

	return nil
}

// Acknowledge menandai peringatan dengan ID tertentu sebagai sudah dibaca.
func (e *Engine) Acknowledge(id int64) error {
	if err := e.db.AcknowledgeAlert(id); err != nil {
		return fmt.Errorf("gagal mengakui peringatan ID %d: %w", id, err)
	}
	slog.Info("peringatan telah ditandai dibaca", "id", id)
	return nil
}

// ARPSpoofing menghasilkan peringatan bahaya saat terdeteksi upaya pemalsuan ARP (ARP spoofing).
func ARPSpoofing(ip, macA, macB string) Alert {
	return Alert{
		Severity:    SeverityDanger,
		Category:    "arp",
		Title:       "Ada perangkat yang berpura-pura jadi router",
		Explanation: "Seseorang di jaringan ini mencoba menyamar sebagai router Anda. Ini bisa membuat lalu lintas internet Anda dibaca orang lain.",
		Action:      "Putuskan koneksi WiFi sekarang. Jangan buka aplikasi bank atau login apa pun sampai Anda pindah ke jaringan lain.",
		Technical:   fmt.Sprintf("IP %s dipetakan ke MAC %s lalu berubah ke %s.", ip, macA, macB),
		DeviceMAC:   macB,
	}
}

// MACSpoofing menghasilkan peringatan bahaya saat terdeteksi alamat MAC yang sama dengan identitas berbeda.
func MACSpoofing(mac, vendorA, vendorB string) Alert {
	return Alert{
		Severity:    SeverityDanger,
		Category:    "mac",
		Title:       "Dua perangkat memakai tanda pengenal yang sama",
		Explanation: "Ada dua perangkat berbeda yang menggunakan alamat fisik jaringan yang sama persis. Hal ini sering terjadi saat seseorang mencoba meniru perangkat lain.",
		Action:      "Hindari berbagi berkas atau memasukkan kata sandi penting. Hubungi pengelola jaringan bila di kantor.",
		Technical:   fmt.Sprintf("MAC %s terdeteksi untuk vendor %s dan %s.", mac, vendorA, vendorB),
		DeviceMAC:   mac,
	}
}

// RogueDHCP menghasilkan peringatan bahaya saat ada server DHCP liar yang mencoba membagikan konfigurasi IP.
func RogueDHCP(serverIP, serverMAC string) Alert {
	return Alert{
		Severity:    SeverityDanger,
		Category:    "dhcp",
		Title:       "Server jaringan tidak dikenal mencoba mengatur koneksi Anda",
		Explanation: "Ada perangkat yang mencoba bertindak sebagai pengatur alamat jaringan (DHCP) palsu. Perangkat ini berpotensi mengarahkan lalu lintas internet Anda ke situs berbahaya.",
		Action:      "Putuskan sambungan dan laporkan ke pengelola jaringan bila berada di tempat kerja atau publik.",
		Technical:   fmt.Sprintf("DHCP offer diterima dari server liar IP %s (MAC %s).", serverIP, serverMAC),
		DeviceMAC:   serverMAC,
	}
}

// GatewayChange menghasilkan peringatan perhatian saat alamat router (gateway) berubah secara mendadak.
func GatewayChange(oldMAC, newMAC string) Alert {
	return Alert{
		Severity:    SeverityAttention,
		Category:    "gateway",
		Title:       "Alamat router utama Anda berubah",
		Explanation: "Koneksi gateway jaringan Anda tiba-tiba berpindah ke perangkat lain. Hal ini wajar jika router baru saja diganti atau di-restart.",
		Action:      "Sambung ulang WiFi Anda untuk memastikan koneksi kembali ke router resmi yang benar.",
		Technical:   fmt.Sprintf("Gateway MAC berubah dari %s menjadi %s.", oldMAC, newMAC),
		DeviceMAC:   newMAC,
	}
}

// SuspiciousDNS menghasilkan peringatan perhatian saat domain mencurigakan diarahkan ke alamat tak lazim.
func SuspiciousDNS(domain, answerIP string) Alert {
	return Alert{
		Severity:    SeverityAttention,
		Category:    "dns",
		Title:       "Pengalihan alamat situs yang mencurigakan",
		Explanation: "Situs web yang diakses diarahkan ke alamat server yang tidak biasa. Ini dapat mengindikasikan upaya pengalihan ke situs tiruan.",
		Action:      "Hindari transaksi online atau memasukkan data pribadi di jaringan ini untuk sementara.",
		Technical:   fmt.Sprintf("Domain %s diarahkan ke IP tidak biasa: %s.", domain, answerIP),
	}
}

// ScriptInjection menghasilkan peringatan bahaya saat terdeteksi penyisipan kode berbahaya dalam lalu lintas web.
func ScriptInjection(host, evidence string) Alert {
	return Alert{
		Severity:    SeverityDanger,
		Category:    "inject",
		Title:       "Penyisipan kode berbahaya dalam halaman web",
		Explanation: "Ditemukan kode yang tidak diinginkan disisipkan ke dalam halaman web yang sedang Anda buka. Ini berpotensi mencuri data pribadi.",
		Action:      "Tutup browser Anda sekarang juga dan jangan login ke akun apa pun sampai Anda berpindah ke jaringan yang aman.",
		Technical:   fmt.Sprintf("Host: %s, Bukti potongan muatan: %s.", host, evidence),
	}
}