// Package connections menyediakan pemantauan koneksi jaringan aktif
// pada perangkat pengguna dalam bahasa Indonesia yang mudah dipahami.
package local

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/shirou/gopsutil/v4/net"
	"shadowscanner/internal/config"
	"shadowscanner/internal/storage"
)

// ConnInfo merekam informasi tentang satu koneksi jaringan aktif
// yang dimiliki oleh proses di mesin pengguna.
type ConnInfo struct {
	Timestamp   time.Time // Waktu koneksi pertama kali terlihat
	Direction   string    // Arah: "keluar" (klien) atau "masuk" (server)
	LocalIP     string    // Alamat IP lokal mesin pengguna
	LocalPort   int       // Port lokal mesin pengguna
	RemoteIP    string    // Alamat IP jarak jauh (bisa lokal atau publik)
	RemotePort  int       // Port jarak jauh
	Protocol    string    // Protokol: "TCP" atau "UDP"
	State       string    // Status koneksi: "ESTABLISHED", "LISTEN", "CLOSE_WAIT", dst.
	ProcessName string    // Nama proses yang membuka koneksi
	ProcessPID  int       // ID proses yang membuka koneksi
}

// Watcher mengelola pemantauan koneksi berkala dan penyimpanan baru
// ke basis data serta pengiriman lewat SSE hub.
type Watcher struct {
	cfg     *config.Config
	db      *storage.DB
	ticker  *time.Ticker
	stopCh  chan struct{}
	lastMap map[string]struct{} // fingerprint koneksi yang sudah dilihat
}

// NewWatcher menciptakan instance Watcher baru dengan konfigurasi dan
// basis data yang diberikan.
func NewWatcher(cfg *config.Config, db *storage.DB) (*Watcher, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if db == nil {
		return nil, fmt.Errorf("database is required")
	}
	return &Watcher{
		cfg:     cfg,
		db:      db,
		ticker:  time.NewTicker(time.Duration(cfg.ScanIntervalSec) * time.Second),
		stopCh:  make(chan struct{}),
		lastMap: make(map[string]struct{}),
	}, nil
}

// Start memulai pemantauan koneksi dalam goroutine terpisah.
// Setiap interval, ambil snapshot koneksi, bandingkan dengan snapshot
// sebelumnya, dan simpan yang baru ke basis data.
func (w *Watcher) Start(ctx context.Context) error {
	go func() {
		// Ambil snapshot awal untuk initialize lastMap
		initial, err := w.Snapshot(ctx)
		if err != nil {
			slog.Error("gagal mengambil snapshot koneksi awal", "error", err)
		} else {
			for _, conn := range initial {
				fp := connFingerprint(conn)
				w.lastMap[fp] = struct{}{}
			}
		}

		for {
			select {
			case <-w.ticker.C:
				snap, err := w.Snapshot(ctx)
				if err != nil {
					slog.Error("gagal mengambil snapshot koneksi", "error", err)
					continue
				}
				var newConns []ConnInfo
				for _, conn := range snap {
					fp := connFingerprint(conn)
					if _, exists := w.lastMap[fp]; !exists {
						newConns = append(newConns, conn)
						w.lastMap[fp] = struct{}{}
					}
				}
				// Simpan koneksi baru ke basis data
				for _, conn := range newConns {
					if err := w.db.InsertConnection(&conn); err != nil {
						slog.Error("gagal menyimpan koneksi baru", "error", err, "conn", conn)
					} else {
						slog.Debug("koneksi baru disimpan", "local_ip", conn.LocalIP, "local_port", conn.LocalPort, "remote_ip", conn.RemoteIP, "remote_port", conn.RemotePort)
					}
				}
				// TODO: Broadcast newConns lewat SSE hub (dihandle di tempat lain)
			case <-w.stopCh:
				w.ticker.Stop()
				return
			case <-ctx.Done():
				w.ticker.Stop()
				return
			}
		}
	}()
	return nil
}

// Stop menghentikan pemantauan koneksi dan membersihkan sumber daya.
func (w *Watcher) Stop() {
	close(w.stopCh)
}

// Snapshot mengembalikan daftar koneksi aktif saat ini.
// Fungsi ini read-only dan tidak mengubah sistem apa pun.
func (w *Watcher) Snapshot(ctx context.Context) ([]ConnInfo, error) {
	var conns []ConnInfo

	// Dapatkan koneksi TCP dan UDP
	tcpConns, err := net.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, fmt.Errorf("get TCP connections: %w", err)
	}
	udpConns, err := net.ConnectionsWithContext(ctx, "udp")
	if err != nil {
		return nil, fmt.Errorf("get UDP connections: %w", err)
	}

	allConns := append(tcpConns, udpConns...)
	for _, c := range allConns {
		// Arah koneksi: masuk jika listen atau port lokal adalah port yang diketahui
		direction := "keluar"
		if c.Status == "LISTEN" || isKnownListenerPort(c.Laddr.Port) {
			direction = "masuk"
		}

		// Dapatkan nama proses
		processName := "Tidak diketahui"
		if c.Pid != 0 {
			if p, err := process.NewProcess(c.Pid); err == nil {
				if name, err := p.Name(); err == nil {
					processName = name
				}
			}
		}

		conn := ConnInfo{
			Timestamp:   time.Unix(0, c.CreateTimestamp*1000000), // gopsutil returns microseconds
			Direction:   direction,
			LocalIP:     c.Laddr.IP,
			LocalPort:   int(c.Laddr.Port),
			RemoteIP:    c.Raddr.IP,
			RemotePort:  int(c.Raddr.Port),
			Protocol:    strings.ToUpper(c.Type),
			State:       c.Status,
			ProcessName: processName,
			ProcessPID:  int(c.Pid),
		}
		conns = append(conns, conn)
	}

	return conns, nil
}

// isKnownListenerPort mengembalikan true jika port merupakan port
// yang umum digunakan untuk layanan yang menerima koneksi.
func isKnownListenerPort(port int) bool {
	// Port umum untuk layanan server
	switch port {
	case 20, 21, // FTP
		22, // SSH
		23, // Telnet
		25, // SMTP
		53, // DNS
		80, // HTTP
		110, // POP3
		139, // NetBIOS
		143, // IMAP
		443, // HTTPS
		445, // SMB
		3306, // MySQL
		3389, // RDP
		5432, // PostgreSQL
		5900, // VNC
		6379, // Redis
		8080, // HTTP alt
		8443: // HTTPS alt
		return true
	}
	return false
}

// connFingerprint menghasilkan string unik untuk mengidentifikasi koneksi
// berdasarkan 5-tuple: local IP, local port, remote IP, remote port, protocol.
func connFingerprint(c ConnInfo) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.Protocol)
}