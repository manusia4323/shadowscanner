# 🛡️ ShadowScanner

**Pengawas Jaringan Lokal Defensif untuk Pengguna Rumah**

ShadowScanner adalah alat desktop keamanan jaringan yang **defensif** dan **read-only**. Alat ini mengawasi jaringan Wi-Fi/LAN rumah Anda secara pasif, mengidentifikasi perangkat yang terhubung, dan memperingatkan Anda tentang aktivitas mencurigakan dalam bahasa Indonesia sederhana yang mudah dipahami pengguna non-teknis.

> **Prinsip utama:** ShadowScanner TIDAK PERNAH menyerang, TIDAK PERNAH menyuntik paket, TIDAK PERNAH memalsukan identitas, dan TIDAK PERNAH memindai di luar subnet Anda sendiri.

---

## 📋 Daftar Isi

- [Tentang ShadowScanner](#tentang-shadowscanner)
- [Fitur Utama](#fitur-utama)
- [Panduan Instalasi](#panduan-instalasi)
- [Cara Penggunaan](#cara-penggunaan)
- [Pengaturan Konfigurasi](#pengaturan-konfigurasi)
- [Antarmuka Web](#antarmuka-web)
- [API Lokal](#api-lokal)
- [Pengembangan](#pengembangan)
- [Batasan Etis](#batasan-etis)
- [Lisensi](#lisensi)

---

## Tentang ShadowScanner

ShadowScanner dirancang khusus untuk pengguna non-teknis yang ingin tahu:

- **Siapa saja yang terhubung ke jaringan rumah saya?**
- **Apakah ada perangkat asing yang tidak saya kenali?**
- **Apakah router saya dipalsukan (ARP spoofing)?**
- **Seberapa jauh perangkat dari komputer saya?**
- **Apakah koneksi internet saya aman?**

Alat ini menjalankan server HTTP lokal di `127.0.0.1` dan menyajikan antarmuka web yang dapat diakses melalui browser. Semua data disimpan secara lokal di komputer Anda menggunakan SQLite.

---

## Fitur Utama

### 🔍 Penemuan Perangkat Pasif
- Membaca tabel ARP/neighbor OS secara pasif (tanpa injeksi paket).
- Cache warmup dengan ICMP ping 1-packet dan throttle 32 goroutine.
- Resolusi reverse DNS dan pencocokan vendor MAC OUI.

### 📱 Identifikasi Perangkat (Fingerprinting)
- Menebak tipe perangkat: Router, Ponsel, Laptop, PC, Printer, TV, Kamera IP, IoT.
- Menggabungkan sinyal lemah: vendor OUI, pola hostname, port yang listen.
- Skor keyakinan (0.0 - 1.0).

### 📏 Estimasi Jarak Fisik
- Model log-distance path loss indoor radio.
- Membaca RSSI WiFi via `iw dev station dump` (Linux) atau `netsh wlan` (Windows).
- Rumus: `d = 10^((TxPower - RSSI) / (10 * n))` dengan TxPower = -30 dBm, n = 2.7.

### 🌐 Deteksi ISP Aman Privasi
- Satu permintaan HTTPS keluar ke `ipinfo.io/json` (fallback `ifconfig.co/json`).
- Timeout 3 detik.
- Dapat dimatikan total (`SHADOWSCANNER_ISP_DISABLED=true`).
- **Tidak pernah** mengirim IP/MAC/hostname lokal atau daftar perangkat.

### ⚠️ Mesin Peringatan
- Deteksi ARP spoofing, duplikasi MAC, rogue DHCP, perubahan gateway, DNS hijacking.
- Peringatan dalam bahasa Indonesia sederhana dengan tingkat bahaya (Bahaya/Peringatan/Info).
- Saran tindakan praktis untuk setiap peringatan.

### 🔌 Pemantau Koneksi Aktif
- Menggunakan `gopsutil/v3` untuk akuntansi proses dan socket.
- Parsing tabel routing dari `/proc/net/route`.
- Streaming real-time via Server-Sent Events (SSE).

### 🖥️ Antarmuka Web Lengkap
- Tema gelap custom, responsif hingga 375px.
- **Nol dependensi CDN eksternal** — semua aset tertanam di binary.
- Topologi radial SVG murni berdasarkan jarak.
- Denah lokasi interaktif (canvas) dengan drag-and-drop.
- Modal persetujuan pengguna (consent) saat pertama dijalankan.

---

## Panduan Instalasi

### Opsi A: Gunakan Binary Pre-built (Disarankan)

Unduh binary untuk sistem operasi Anda dari folder `dist/`:

| Platform | File |
|---|---|
| Linux 64-bit | `shadowscanner-linux-amd64` |
| Linux ARM64 | `shadowscanner-linux-arm64` |
| Windows 64-bit | `shadowscanner-windows-amd64.exe` |
| Windows ARM64 | `shadowscanner-windows-arm64.exe` |

**Linux:**
```bash
chmod +x shadowscanner-linux-amd64
./shadowscanner-linux-amd64
```

**Windows:**
Klik dua kali `shadowscanner-windows-amd64.exe` atau jalankan dari Command Prompt.

Browser akan otomatis terbuka ke `http://127.0.0.1:8787`.

### Opsi B: Build dari Source

**Prasyarat:**
- Go 1.21 atau lebih baru.

```bash
# Clone repository
git clone <repo-url>
cd shadowscanner

# Build untuk platform saat ini
go build -o shadowscanner ./main.go

# Atau gunakan skrip build
bash scripts/build-linux.sh      # Linux
bash scripts/build-windows.sh    # Windows
bash scripts/build-all.sh        # Semua platform
```

---

## Cara Penggunaan

1. **Jalankan ShadowScanner** — browser akan terbuka otomatis.
2. **Baca modal persetujuan** dan klik "Saya Mengerti & Setuju".
3. **Klik "🔍 Pindai Jaringan"** di pojok kanan atas untuk memulai pemindaian.
4. **Jelajahi tab:**
   - **Ringkasan** — status jaringan dan host Anda.
   - **Perangkat** — daftar semua perangkat yang terdeteksi.
   - **Topologi** — visualisasi radial berdasarkan jarak.
   - **Denah Lokasi** — petakan posisi perangkat di rumah Anda.
   - **Peringatan** — peringatan keamanan dan saran tindakan.
   - **Koneksi** — koneksi jaringan aktif per proses.
   - **Riwayat** — riwayat pemindaian dan pengaturan.

---

## Pengaturan Konfigurasi

ShadowScanner dapat dikonfigurasi melalui file `.env` atau variabel environment:

| Variabel Environment | Default | Deskripsi |
|---|---|---|
| `SHADOWSCANNER_PORT` | `8787` | Port server HTTP lokal |
| `SHADOWSCANNER_LOG_LEVEL` | `info` | Level log (`debug`, `info`, `warn`, `error`) |
| `SHADOWSCANNER_DB_PATH` | `shadowscanner.db` | Path file database SQLite |
| `SHADOWSCANNER_RETENTION_HOURS` | `8` | Durasi retensi data (jam) |
| `SHADOWSCANNER_SCAN_INTERVAL_SEC` | `60` | Interval pemindaian otomatis (detik) |
| `SHADOWSCANNER_MAX_DEVICES` | `256` | Batas maksimum perangkat disimpan |
| `SHADOWSCANNER_ISP_DISABLED` | `false` | Matikan deteksi ISP |
| `SHADOWSCANNER_WARNING_MODE` | `true` | Mode peringatan santai |

Contoh file `.env`:
```env
SHADOWSCANNER_PORT=8787
SHADOWSCANNER_LOG_LEVEL=info
SHADOWSCANNER_DB_PATH=shadowscanner.db
SHADOWSCANNER_RETENTION_HOURS=8
SHADOWSCANNER_ISP_DISABLED=false
```

---

## Antarmuka Web

Antarmuka web disajikan dari `http://127.0.0.1:8787` dan terdiri dari:

- **`/`** — Halaman utama (SPA single-page dashboard)
- **`/assets/css/style.css`** — Stylesheet dark theme
- **`/assets/js/app.js`** — Controller SPA & hash routing
- **`/assets/js/api.js`** — Klien Fetch & EventSource (SSE)
- **`/assets/js/graph.js`** — Visualisasi SVG radial
- **`/assets/js/floorplan.js`** — Canvas denah interaktif
- **`/assets/js/alerts.js`** — Rendering kartu peringatan
- **`/assets/js/i18n.js`** — Kamus Bahasa Indonesia

Semua aset tertanam ke dalam binary menggunakan `//go:embed` — tidak ada file eksternal yang diperlukan saat distribusi.

---

## API Lokal

Semua endpoint terikat pada `127.0.0.1` (tidak dapat diakses dari luar).

| Method | Endpoint | Deskripsi |
|---|---|---|
| GET | `/api/health` | Status kesehatan server |
| GET | `/api/self` | Info perangkat lokal (host, IP, gateway, ISP) |
| GET | `/api/devices` | Daftar perangkat yang terdeteksi |
| GET | `/api/alerts` | Daftar peringatan keamanan |
| POST | `/api/alerts/acknowledge?id=N` | Tandai peringatan sebagai dibaca |
| GET | `/api/connections` | Daftar koneksi jaringan aktif |
| GET | `/api/connections/stream` | SSE stream koneksi real-time |
| GET | `/api/alerts/stream` | SSE stream peringatan real-time |
| GET | `/api/history` | Riwayat pemindaian |
| POST | `/api/retention?hours=N` | Atur durasi retensi data |
| GET | `/api/recommendations` | Saran tindakan keamanan |
| POST | `/api/scan/start` | Mulai pemindaian manual |
| POST | `/api/scan/stop` | Hentikan pemindaian aktif |
| GET/POST | `/api/settings` | Baca/simpan pengaturan |

---

## Pengembangan

### Struktur Proyek

```
shadowscanner/
├── main.go                     # Entry point daemon
├── go.mod / go.sum             # Modul Go
├── internal/
│   ├── api/                    # Server HTTP & SSE hub
│   │   ├── server.go
│   │   ├── routes.go
│   │   ├── sse.go
│   │   └── api_test.go
│   ├── alert/                  # Mesin peringatan & saran
│   │   ├── alert.go
│   │   └── alert_test.go
│   ├── scanner/                # Engine pemindaian pasif
│   │   ├── discovery.go
│   │   ├── ports.go
│   │   ├── fingerprint.go
│   │   ├── distance.go
│   │   ├── isp.go
│   │   └── scanner_test.go
│   ├── storage/                # Database SQLite (modernc.org/sqlite)
│   │   ├── db.go
│   │   └── db_test.go
│   ├── local/                  # Inspeksi host & pemantau koneksi
│   │   ├── selfinfo.go
│   │   ├── watcher.go
│   │   └── local_test.go
│   ├── config/                 # Konfigurasi & validasi
│   │   ├── config.go
│   │   └── config_test.go
│   ├── history/                # Retensi & pembersihan data
│   │   ├── retention.go
│   │   └── retention_test.go
│   └── ui/                     # Aset web tertanam (//go:embed)
│       ├── embed.go
│       └── assets/
│           ├── index.html
│           ├── css/style.css
│           └── js/{app,api,alerts,graph,floorplan,i18n}.js
├── scripts/                    # Skrip build cross-compilation
│   ├── build-linux.sh
│   ├── build-windows.sh
│   └── build-all.sh
├── dist/                       # Output binary (dibuat oleh skrip)
├── README.md
└── LICENSE
```

### Menjalankan Tests

```bash
# Jalankan semua unit test
go test -v ./...

# Build seluruh paket
go build ./...

# Vet kode
go vet ./...
```

### Build Cross-Compilation

```bash
# Linux saja
bash scripts/build-linux.sh

# Windows saja
bash scripts/build-windows.sh

# Semua platform (Linux, Windows, macOS)
bash scripts/build-all.sh
```

Binary statis dihasilkan dengan `CGO_ENABLED=0` — tidak ada dependensi C library. Semua aset UI tertanam via `//go:embed`.

---

## Batasan Etis

ShadowScanner adalah alat **defensif**. Berikut batasan ketat yang diterapkan:

| ❌ Dilarang | ✓ Diizinkan |
|---|---|
| ARP spoofing | Membaca tabel ARP OS |
| MAC spoofing | Membaca MAC dari neighbor table |
| Packet injection | ICMP ping 1-packet untuk warmup cache |
| Deauthentication | Membaca RSSI WiFi pasif |
| SYN flood / full port scan | Memeriksa 11 port umum dengan koneksi penuh |
| Eksploitasi apa pun | Membaca tabel routing & koneksi OS |
| Pemindaian luar subnet | Pemindaian hanya /24 lokal |
| Mengirim data lokal keluar | Satu HTTPS ke ipinfo.io (opsional, dapat dimatikan) |

**Daftar port tetap (JANGAN tambah):** 21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080, 8443.

**Server hanya mendengarkan `127.0.0.1`** — tidak ada akses dari jaringan luar.

---

## Lisensi

Lisensi MIT — lihat file [LICENSE](LICENSE).

---

**Dibuat untuk pengguna rumah yang ingin merasa aman di jaringan mereka sendiri.** 🏠🔒
