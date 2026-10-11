// Package engine mengubah sinyal mentah dari scanner dan watcher menjadi
// peringatan berbasis bahasa Indonesia dengan tingkat keparahan yang jelas.
package alert

import (
	"context"
	"time"

	"shadowscanner/internal/storage"
)

// Severity menampilkan tingkat keparahan peringatan.
type Severity string

const (
	// Aman: tidak ada tindakan yang diperlukan.
	SeveritySafe Severity = "aman"
	// Perhatian: ada sesuatu yang perlu diperhatikan tetapi tidak berbahaya.
	SeverityAttention Severity = "perhatian"
	// Bahaya: tindakan segera diperlukan untuk melindungi diri.
	SeverityDanger Severity = "bahaya"
)

// Alert merekam satu peringatan keamanan yang dapat ditampilkan kepada pengguna
// dalam bahasa Indonesia yang mudah dipahami.
type Alert struct {
	ID          int64     // Kunci utama SQLite (auto-increment)
	Timestamp   time.Time // Waktu peringatan dibuat (diisi oleh Raise jika nol)
	Severity    Severity  // Tingkat keparahan: "aman", "perhatian", "bahaya"
	Category    string    // Jenis peringatan: "arp", "mac", "dhcp", "dns", "gateway", "inject"
	Title       string    // Judul singkat dalam bahasa Indonesia (maks. 8 kata)
	Explanation string    // Penjelasan 2-3 kalimat dalam bahasa Indonesia tanpa jargon
	Action      string    // Langkah konkret 1-3 dalam bahasa Indonesia untuk pengguna
	Technical   string    // Detail teknis (IP, MAC, port) untuk pengguna lanjutan
	DeviceMAC   string    // MAC perangkat terkait (jika ada)
}

// Engine mengelola pembuatan dan penyimpanan peringatan.
type Engine struct {
	db *storage.DB
}

// NewEngine menciptakan instance Engine baru.
func NewEngine(db *storage.DB) *Engine {
	return &Engine{db: db}
}

// Raise menyimpan satu Alert ke basis data dan (di masa mendatang)
// menyebarkannya melalui hub SSE. Jika timestamp Alert adalah nol,
// waktu saat ini akan digunakan.
func (e *Engine) Raise(ctx context.Context, a Alert) error {
	// Apabila timestamp belum diisi, gunakan waktu sekarang.
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}

	// Validasi ringan: pastikan string wajib tidak kosong.
	if a.Title == "" || a.Explanation == "" || a.Action == "" {
		return fmt.Errorf("alert harus memiliki title, explanation, dan action")
	}

	// Simpan ke basis data.
	if _, err := e.db.InsertAlert(&a); err != nil {
		return fmt.Errorf("gagal menyimpan alert: %w", err)
	}

	// Di sini seharusnya ada notifikasi ke SSE hub.
	// Untuk saat ini, cukup log bahwa alert telah dibuat.
	slog.Info("alert dibuat",
		"id", a.ID,
		"severity", a.Severity,
		"category", a.Category,
		"title", a.Title)

	return nil
}

// Acknowledge menandai Alert dengan ID tertentu sebagai sudah dibaca
// (acknowledged = true).
func (e *Engine) Acknowledge(ctx context.Context, id int64) error {
	if err := e.db.AcknowledgeAlert(id); err != nil {
		return fmt.Errorf("gagal mengakui alert: %w", err)
	}
	return nil
}

// ----- Predefined alert constructors (templates dalam bahasa Indonesia) -----

// ARPSpoofing mengembalikan Alert untuk kecurangan ARP (seorang perangkat
// berpura-pura menjadi gateway).
func ARPSpoofing(ip, macA, macB string) Alert {
	return Alert{
		Severity: SeverityDanger,
		Category: "arp",
		Title:    "Ada perangkat yang berpura-pura jadi router",
		Explanation: "Seseorang di jaringan ini mencoba menyamar sebagai router " +
			"Anda. Ini bisa membuat lalu lintas internet Anda dibaca orang lain.",
		Action:   "Putuskan koneksi WiFi sekarang. Jangan buka aplikasi bank atau " +
			"login apa pun sampai Anda pindah ke jaringan lain.",
		Technical: fmt.Sprintf("IP %s dipetakan ke MAC %s lalu berubah ke %s.", ip, macA, macB),
		DeviceMAC: macB,
	}
}

// MACSpoofing mengembalikan Alert untuk kecurangan MAC (dua perangkat
// menggunakan MAC yang sama).
func MACSpoofing(mac, vendorA, vendorB string) Alert {
	return Alert{
		Severity: SeverityDanger,
		Category: "mac",
		Title:    "Dua perangkat menggunakan alamat MAC yang sama",
		Explanation: "Dua perangkat berbeda dalam jaringan ini menggunakan " +
			"alamat MAC identik. Ini mungkin menunjukkan kecurangan atau " +
			"konfigurasi yang salah.",
		Action:   "Periksa perangkat yang terhubung ke jaringan. Jika Anda tidak " +
			"mengenali satu perangkat, putuskan koneksinya dari jaringan.",
		Technical: fmt.Sprintf("MAC %s digunakan oleh perangkat dengan vendor '%s' " +
			"dan juga oleh perangkat dengan vendor '%s'.", mac, vendorA, vendorB),
		DeviceMAC: mac,
	}
}

// RogueDHCP mengembalikan Alert untuk server DHCP tidak sah yang mungkin
// memberikan konfigurasi jaringan berbahaya.
func RogueDHCP(serverIP, serverMAC string) Alert {
	return Alert{
		Severity: SeverityDanger,
		Category: "dhcp",
		Title:    "Server DHCP tidak terdeteksi sebelumnya aktif",
		Explanation: "Ada perangkat yang berper sebagai server DHCP tanpa " +
			"izin atau tidak dikenal sebelumnya dalam jaringan Anda. " +
			"Perangkat ini bisa memberikan konfigurasi jaringan yang mengarahkan " +
			"lalu lintas Anda ke jalur yang tidak diinginkan.",
		Action:   "Matikan perangkat yang memberikan layanan DHCP ini jika Anda " +
			"tidak mengenalnya. Laporkan ke pengelola jaringan jika Anda di kantor " +
			" atau jaringan publik.",
		Technical: fmt.Sprintf("Server DHCP beralamat IP %s dengan MAC %s", serverIP, serverMAC),
		DeviceMAC: serverMAC,
	}
}

// GatewayChange mengembalikan Alert ketika MAC gateway berubah secara
// tiba-tiba (mungkin indikasi seranganMan-in-the-Middle).
func GatewayChange(oldMAC, newMAC string) Alert {
	return Alert{
		Severity: SeverityAttention,
		Category: "gateway",
		Title:    "Perangkat gateway telah berubah",
		Explanation: "Perangkat yang biasa Anda gunakan sebagai gateway " +
			"(router ke internet) telah berubah alamat MAC-nya. " +
			"Ini bisa normal jika Anda baru saja mengganti router, " +
			"tapi juga bisa menjadi indikasi seseorang mencoba menyintersept " +
			"lalu lintas Anda.",
		Action:   "Verifikasi bahwa perubahan ini sengaja Anda lakukan. " +
			"Jika tidak, putuskan dari jaringan dan mulai ulang router Anda.",
		Technical: fmt.Sprintf("Gateway MAC berubah dari %s menjadi %s", oldMAC, newMAC),
		DeviceMAC: newMAC,
	}
}

// SuspiciousDNS mengembalikan Alert ketika terdapat respons DNS ke domain
// yang terkait dengan aktivitas berbahaya.
func SuspiciousDNS(domain, answerIP string) Alert {
	return Alert{
		Severity: SeverityAttention,
		Category: "dns",
		Title:    "Permintaan DNS ke domain mencurigakan",
		Explanation: "Ada perangkat dalam jaringan Anda yang melakukan " +
			"permintaan nama domain yang sering dikaitkan dengan malware, " +
			"phishing, atau aktivitas berbahaya lainnya. " +
			"Domain yang diminta: " + domain,
		Action:   "Periksa perangkat yang membuat permintaan DNS ini. " +
			"Jika tidak dikenal, pertimbangkan untuk memutuskan koneksinya " +
			"dari jaringan sementara waktu.",
		Technical: fmt.Sprintf("DNS request for %s returned IP %s", domain, answerIP),
	}
}

// ScriptInjection mengembalikan Alert ketika terdeteksi upaya penyisipan
// skrip dalam lalu lintas HTTP (indikasi XSS atau middleware berbahaya).
func ScriptInjection(host, evidence string) Alert {
	return Alert{
		Severity: SeverityDanger,
		Category: "inject",
		Title:    "Terdeteksi upaya penyisipan skrip dalam lalu lintas",
		Explanation: "Ada indikasi bahwa seseorang dalam jaringan ini mencoba " +
			"menyisipkan kode berbahaya ke dalam lalu lintas HTTP Anda. " +
			"Ini bisa berupa upaya mencuri cookie, session token, atau data " +
			"sensitif lainnya.",
		Action:   "Segera tutup semua tab browser dan jangan masuk ke situs " +
			"apapun yang membutuhkan login sampai Anda pindah ke jaringan lain " +
			"dan membersihkan cache browser Anda.",
		Technical: fmt.Sprintf("Host: %s, Evidence: %s", host, evidence),
	}
}