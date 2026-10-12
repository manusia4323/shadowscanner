// Package alert menyediakan logika pembentukan rekomendasi praktis
// bagi pengguna awam berdasarkan kondisi dan temuan jaringan.
package alert

import (
	"fmt"

	"github.com/google/uuid"
	"shadowscanner/internal/storage"
)

// Recommendation menyajikan satu saran tindakan konkret dalam bahasa Indonesia
// dengan penjelasan sederhana mengapa tindakan tersebut disarankan.
type Recommendation struct {
	ID       string   // Pengenal unik rekomendasi
	Title    string   // Judul rekomendasi yang singkat dan jelas
	Why      string   // Penjelasan alasan di balik rekomendasi dalam bahasa sederhana
	Steps    []string // Langkah-langkah bernomor yang dapat segera dilakukan
	Severity Severity // Tingkat urgensi saran: "aman", "perhatian", atau "bahaya"
}

// Generate menyusun daftar rekomendasi dari kumpulan peringatan aktif dan perangkat terdaftar.
func Generate(alerts []Alert, devices []storage.Device) []Recommendation {
	var recs []Recommendation
	seenTitles := make(map[string]bool)

	addRec := func(title, why string, steps []string, sev Severity) {
		if seenTitles[title] {
			return
		}
		seenTitles[title] = true
		recs = append(recs, Recommendation{
			ID:       uuid.New().String(),
			Title:    title,
			Why:      why,
			Steps:    steps,
			Severity: sev,
		})
	}

	hasDanger := false
	hasARPSpoof := false
	hasRogueDHCP := false
	hasMACSpoof := false
	hasGatewayChange := false
	hasSuspiciousDNS := false
	hasScriptInject := false

	for _, a := range alerts {
		if a.Severity == SeverityDanger {
			hasDanger = true
		}
		switch a.Category {
		case "arp":
			hasARPSpoof = true
		case "dhcp":
			hasRogueDHCP = true
		case "mac":
			hasMACSpoof = true
		case "gateway":
			hasGatewayChange = true
		case "dns":
			hasSuspiciousDNS = true
		case "inject":
			hasScriptInject = true
		}
	}

	// 1. Any "bahaya" alert active -> "Pindah ke jaringan lain"
	if hasDanger {
		addRec(
			"Pindah ke jaringan lain",
			"Terdeteksi ancaman aktif yang dapat membahayakan privasi dan data akun pribadi Anda di jaringan ini.",
			[]string{
				"Matikan sambungan Wi-Fi atau cabut kabel LAN komputer Anda.",
				"Beralihlah ke jaringan tethering ponsel atau koneksi lain yang terpercaya.",
				"Hindari membuka layanan perbankan atau email sebelum berpindah jaringan.",
			},
			SeverityDanger,
		)
	}

	// 2. ARP spoofing detected -> "Putuskan koneksi sekarang"
	if hasARPSpoof {
		addRec(
			"Putuskan koneksi sekarang",
			"Ada perangkat yang mencoba menyamar sebagai router untuk membaca lalu lintas internet Anda.",
			[]string{
				"Putuskan Wi-Fi perangkat Anda seketika.",
				"Jangan memasukkan username atau password apa pun di peramban.",
				"Gunakan koneksi data seluler pribadi untuk keperluan mendesak.",
			},
			SeverityDanger,
		)
	}

	// 3. Script injection detected -> "Tutup browser dan jangan login"
	if hasScriptInject {
		addRec(
			"Tutup browser dan jangan login",
			"Terdapat upaya penyisipan kode asing ke dalam halaman web yang Anda kunjungi.",
			[]string{
				"Tutup seluruh tab peramban yang sedang terbuka.",
				"Jangan menekan tombol login atau mengisi formulir data rahasia.",
				"Bersihkan riwayat dan cache peramban setelah pindah koneksi.",
			},
			SeverityDanger,
		)
	}

	// 4. Rogue DHCP detected -> "Laporkan ke pengelola jaringan"
	if hasRogueDHCP {
		addRec(
			"Laporkan ke pengelola jaringan",
			"Ditemukan server pengatur alamat jaringan liar yang mencoba mengontrol sambungan komputer Anda.",
			[]string{
				"Beri tahu staf IT atau pemilik tempat bahwa terdeteksi DHCP liar di jaringan.",
				"Putuskan koneksi sampai pengelola jaringan mengatasi perangkat tersebut.",
			},
			SeverityDanger,
		)
	}

	// 5. MAC spoofing detected -> "Hindari berbagi file di jaringan ini"
	if hasMACSpoof {
		addRec(
			"Hindari berbagi file di jaringan ini",
			"Ada dua perangkat berbeda yang menggunakan alamat identitas yang serupa.",
			[]string{
				"Nonaktifkan fitur File Sharing dan Network Discovery di komputer Anda.",
				"Gunakan media penyimpanan fisik jika perlu memindahkan berkas.",
			},
			SeverityAttention,
		)
	}

	// 6. Gateway change detected -> "Sambung ulang WiFi"
	if hasGatewayChange {
		addRec(
			"Sambung ulang WiFi",
			"Alamat router utama terdeteksi berubah, kemungkinan router di-restart atau dialihkan.",
			[]string{
				"Matikan Wi-Fi selama 5 detik lalu hidupkan kembali.",
				"Pastikan nama jaringan (SSID) yang terhubung adalah jaringan resmi yang benar.",
			},
			SeverityAttention,
		)
	}

	// 7. Suspicious DNS detected -> "Hindari transaksi online di jaringan ini"
	if hasSuspiciousDNS {
		addRec(
			"Hindari transaksi online di jaringan ini",
			"Pencarian alamat situs menunjukkan indikasi pengalihan ke tujuan yang mencurigakan.",
			[]string{
				"Tunda transaksi perbankan atau pembayaran digital sampai koneksi terjamin aman.",
				"Pastikan alamat situs selalu diawali 'https://' dan memiliki lambang gembok terkunci.",
			},
			SeverityAttention,
		)
	}

	// 8. Kondisi perangkat mencurigakan dari daftar devices
	if len(devices) > 50 {
		addRec(
			"Waspada keramaian perangkat di jaringan publik",
			fmt.Sprintf("Terdeteksi %d perangkat dalam satu subnet. Jaringan yang sangat ramai lebih rentan disusupi.", len(devices)),
			[]string{
				"Pastikan firewall sistem operasi Anda selalu dalam status aktif.",
				"Gunakan layanan VPN terpercaya jika harus bekerja di jaringan publik.",
			},
			SeverityAttention,
		)
	}

	// 9. Default jika tidak ada peringatan khusus
	if len(recs) == 0 {
		addRec(
			"Jaringan terlihat normal",
			"Tidak ditemukan kejanggalan atau aktivitas mencurigakan pada pemindaian terakhir.",
			[]string{
				"Tetap aktifkan pemantauan otomatis ShadowScanner saat berada di jaringan baru.",
				"Pastikan kata sandi Wi-Fi dan perangkat Anda menggunakan kombinasi yang kuat.",
				"Perbarui sistem operasi secara teratur untuk menutup celah keamanan.",
			},
			SeveritySafe,
		)
	}

	return recs
}