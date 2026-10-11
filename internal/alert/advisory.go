// Package advisory menghasilkan rekomendasi berbasis bahasa Indonesia
// berdasarkan keadaan jaringan dan peringatan yang aktif.
package alert

import (
	"github.com/google/uuid"
	"shadowscanner/internal/storage"
)

// Recommendation merepresentasikan satu nasihat praktis untuk pengguna.
type Recommendation struct {
	ID       string    // Identifier unik untuk rekomendasi ini
	Title    string    // Judul singkat, maksimal 6 kata
	Why      string    // "Kenapa?" penjelasan singkat dalam bahasa Indonesia
	Steps    []string  // Langkah-langkah yang bisa diambil pengguna
	Severity Severity  // Tingkat keparahan yang sesuai
}

// Generate menghasilkan rekomendasi berdasarkan daftar peringatan
// dan perangkat yang terdeteksi. Jika ada peringatan berbahaya,
// rekomendasi paling penting akan ditempatkan pertama.
func Generate(alerts []Alert, devices []storage.Device) []Recommendation {
	var recs []Recommendation
	seenIDs := make(map[string]struct{})

	// Cek semua peringatan yang ada
	for _, a := range alerts {
		switch a.Category {
		case "arp":
			if addUnique(recs, seenIDs, mk("Pindah ke jaringan lain",
				"ARP spoofing berarti seseorang menyehingginkan ia bisa membaca semua lalu lintas internet Anda.",
				[]string{"Putuskan WiFi sekarang", "Hubungkan ke jaringan lain (misalnya hotspot ponsel)", "Periksa router Anda untuk pengaturan yang mencurigakan"},
				SeverityDanger)) {
				recs = append(recs, mk("Pindah ke jaringan lain",
					"ARP spoofing berarti seseorang menyehingginkan ia bisa membaca semua lalu lintas internet Anda.",
					[]string{"Putuskan WiFi sekarang", "Hubungkan ke jaringan lain (misalnya hotspot ponsel)", "Periksa router Anda untuk pengaturan yang mencurigakan"},
					SeverityDanger))
			}
		case "dhcp":
			if addUnique(recs, seenIDs, mk("Laporkan ke pengelola jaringan",
				"Server DHCP tidak sah bisa memberikan konfigurasi jaringan yang mengarahkan lalu lintas Anda ke jalur yang salah.",
				[]string{"Matikan perangkat tak terduga yang tersambung", "Hubungi pengelola jaringan Anda", "Periksa router untuk port yang tidak dikenal"},
				SeverityDanger)) {
				recs = append(recs, mk("Laporkan ke pengelola jaringan",
					"Server DHCP tidak sah bisa memberikan konfigurasi jaringan yang mengarahkan lalu lintas Anda ke jalur yang salah.",
					[]string{"Matikan perangkat tak terduga yang tersambung", "Hubungi pengelola jaringan Anda", "Periksa router untuk port yang tidak dikenal"},
					SeverityDanger))
			}
		case "inject":
			if addUnique(recs, seenIDs, mk("Tutup browser dan jangan login",
				"Penyisipan skrip berarti seseorang mencoba mencuri data dari browser Anda.",
				[]string{"Tutup semua tab browser", "Jangan login ke situs apapun sampai beralih jaringan", "Bersihkan cache dan cookie browser setelah pindah jaringan"},
				SeverityDanger)) {
				recs = append(recs, mk("Tutup browser dan jangan login",
					"Penyisipan skrip berarti seseorang mencoba mencuri data dari browser Anda.",
					[]string{"Tutup semua tab browser", "Jangan login ke situs apapun sampai beralih jaringan", "Bersihkan cache dan cookie browser setelah pindah jaringan"},
					SeverityDanger))
			}
		case "gateway":
			if addUnique(recs, seenIDs, mk("Sambung ulang WiFi Anda",
				"Perubahan gateway berarti perangkat yang menghubungkan Anda ke internet telah berubah.",
				[]string{"Putuskan dan sambungkan kembali WiFi", "Periksa apakah Anda baru saja mengganti router", "Jika tidak sengaja, perhatikan lalu lintas Anda"},
				SeverityAttention)) {
				recs = append(recs, mk("Sambung ulang WiFi Anda",
					"Perubahan gateway berarti perangkat yang menghubungkan Anda ke internet telah berubah.",
					[]string{"Putuskan dan sambungkan kembali WiFi", "Periksa apakah Anda baru saja mengganti router", "Jika tidak sengaja, perhatikan lalu lintas Anda"},
					SeverityAttention))
			}
		case "mac":
			if addUnique(recs, seenIDs, mk("Hindari berbagi file",
				"Duplikasi MAC berarti ada perangkat yang tak Terduga dalam jaringan Anda.",
				[]string{"Putuskan perangkat yang tidak dikenali dari jaringan", "Gunakan jaringan terpisah untuk berbagi file", "Periksa pengaturan router Anda"},
				SeverityAttention)) {
				recs = append(recs, mk("Hindari berbagi file",
					"Duplikasi MAC berarti ada perangkat yang tidak terduga dalam jaringan Anda.",
					[]string{"Putuskan perangkat yang tidak dikenali dari jaringan", "Gunakan jaringan terpisah untuk berbagi file", "Periksa pengaturan router Anda"},
					SeverityAttention))
			}
		case "dns":
			if addUnique(recs, seenIDs, mk("Hindari transaksi online",
				"Permintaan DNS mencurigakan berarti ada perangkat yang mencoba menghubungi server berbahaya.",
					"Tidak ada rekomendasi khusus, jaringan Anda terlihat normal."},
			Severity: SeveritySafe,
		})
	}

	// Pastikan ada setidaknya satu rekomendasi
	if len(recs) == 0 {
		recs = append(recs, defaultRecommendation())
	}

	return recs
}

// mk adalah helper untuk menciptakan Recommendation dengan ID unik.
func mk(title, why string, steps []string, sev Severity) Recommendation {
	return Recommendation{
		ID:       uuid.New().String(),
		Title:    title,
		Why:      why,
		Steps:    steps,
		Severity: sev,
	}
}

// addUnique menambahkan rekomendasi ke slice dan mengembalikan true jika
// berhasil ditambahkan (ID belum ada di seenIDs).
func addUnique(recs *[]Recommendation, seen map[string]struct{}, rec Recommendation) bool {
	if _, ok := seen[rec.ID]; ok {
		return false
	}
	seen[rec.ID] = struct{}{}
	*recs = append(*recs, rec)
	return true
}

// defaultRecommendation mengembalikan rekomendasi default ketika tidak ada
// peringatan yang perlu diwaspadai.
func defaultRecommendation() Recommendation {
	return Recommendation{
		ID:    uuid.New().String(),
		Title: "Jaringan terlihat normal",
		Why:   "Tidak ada aktivitas mencurigakan yang terdeteksi pada jaringan Anda saat ini.",
		Steps: []string{
			"Pantau peringatan secara berkala",
			"Perbarui router dan perangkat Anda secara rutin",
			"Gunakan koneksi terenkripsi (HTTPS, VPN) untuk kegiatan sensitif"},
		Severity: SeveritySafe,
	}
}