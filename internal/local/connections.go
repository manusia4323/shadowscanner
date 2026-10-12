// Package local menyediakan pemantauan koneksi jaringan aktif
// pada perangkat pengguna dalam bahasa Indonesia yang mudah dipahami.
package local

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
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

// Broadcaster mendefinisikan antarmuka untuk menyiarkan koneksi baru ke SSE hub.
type Broadcaster interface {
	Broadcast(event string, data any)
}

// Watcher mengelola pemantauan koneksi berkala dan penyimpanan koneksi baru
// ke basis data serta siaran lewat SSE hub.
type Watcher struct {
	cfg         *config.Config
	db          *storage.DB
	ticker      *time.Ticker
	stopCh      chan struct{}
	mu          sync.Mutex
	lastMap     map[string]struct{}
	running     bool
	broadcaster Broadcaster
}

// NewWatcher menciptakan instance Watcher baru dengan konfigurasi dan basis data yang diberikan.
func NewWatcher(cfg *config.Config, db *storage.DB) (*Watcher, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config tidak boleh nil")
	}
	if db == nil {
		return nil, fmt.Errorf("storage db tidak boleh nil")
	}
	interval := cfg.ScanIntervalSec
	if interval < 10 {
		interval = 60
	}
	return &Watcher{
		cfg:     cfg,
		db:      db,
		ticker:  time.NewTicker(time.Duration(interval) * time.Second),
		stopCh:  make(chan struct{}),
		lastMap: make(map[string]struct{}),
	}, nil
}

// SetBroadcaster menetapkan broadcaster SSE untuk mengirim event koneksi baru.
func (w *Watcher) SetBroadcaster(b Broadcaster) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.broadcaster = b
}

// Start memulai pemantauan koneksi dalam goroutine berkala.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("watcher sudah berjalan")
	}
	w.running = true
	w.mu.Unlock()

	// Snapshot awal untuk mengisi map perbandingan
	initial, err := w.Snapshot()
	if err == nil {
		w.mu.Lock()
		for _, conn := range initial {
			w.lastMap[connFingerprint(conn)] = struct{}{}
		}
		w.mu.Unlock()
	} else {
		slog.Warn("gagal mengambil snapshot koneksi awal", "error", err)
	}

	go func() {
		for {
			select {
			case <-w.ticker.C:
				current, err := w.Snapshot()
				if err != nil {
					slog.Warn("gagal mengambil snapshot koneksi", "error", err)
					continue
				}

				var newConns []ConnInfo
				w.mu.Lock()
				for _, conn := range current {
					fp := connFingerprint(conn)
					if _, exists := w.lastMap[fp]; !exists {
						w.lastMap[fp] = struct{}{}
						newConns = append(newConns, conn)
					}
				}
				broadcaster := w.broadcaster
				w.mu.Unlock()

				// Simpan hanya koneksi baru ke basis data
				for _, conn := range newConns {
					dbConn := &storage.Connection{
						Timestamp:   conn.Timestamp,
						Direction:   conn.Direction,
						LocalIP:     conn.LocalIP,
						LocalPort:   conn.LocalPort,
						RemoteIP:    conn.RemoteIP,
						RemotePort:  conn.RemotePort,
						Protocol:    conn.Protocol,
						ProcessName: conn.ProcessName,
						ProcessPID:  conn.ProcessPID,
						State:       conn.State,
					}
					if err := w.db.InsertConnection(dbConn); err != nil {
						slog.Debug("catatan: gagal menyimpan koneksi", "error", err)
					}
					if broadcaster != nil {
						broadcaster.Broadcast("connection", conn)
					}
				}

			case <-w.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Stop menghentikan pemantauan koneksi dan membersihkan timer.
func (w *Watcher) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return nil
	}
	w.running = false
	w.ticker.Stop()
	close(w.stopCh)
	return nil
}

// Snapshot mengembalikan daftar koneksi aktif saat ini.
// Fungsi ini read-only dan aman dari segi hak akses.
func (w *Watcher) Snapshot() ([]ConnInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tcpConns, err := net.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, fmt.Errorf("gagal membaca koneksi TCP: %w", err)
	}

	udpConns, _ := net.ConnectionsWithContext(ctx, "udp")
	allConns := append(tcpConns, udpConns...)

	now := time.Now()
	var results []ConnInfo

	for _, c := range allConns {
		direction := "keluar"
		if c.Status == "LISTEN" || isKnownListenerPort(int(c.Laddr.Port)) {
			direction = "masuk"
		}

		procName := "Tidak diketahui"
		if c.Pid > 0 {
			if p, err := process.NewProcess(c.Pid); err == nil {
				if n, err := p.Name(); err == nil && n != "" {
					procName = n
				}
			}
		} else if c.Pid == 0 {
			procName = "Tidak diketahui (butuh izin)"
		}

		proto := "TCP"
		if c.Type == 2 {
			proto = "UDP"
		}

		conn := ConnInfo{
			Timestamp:   now,
			Direction:   direction,
			LocalIP:     c.Laddr.IP,
			LocalPort:   int(c.Laddr.Port),
			RemoteIP:    c.Raddr.IP,
			RemotePort:  int(c.Raddr.Port),
			Protocol:    proto,
			State:       c.Status,
			ProcessName: procName,
			ProcessPID:  int(c.Pid),
		}
		results = append(results, conn)
	}

	return results, nil
}

// isKnownListenerPort memeriksa apakah port termasuk port layanan yang biasa menerima koneksi.
func isKnownListenerPort(port int) bool {
	switch port {
	case 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080, 8443:
		return true
	default:
		return false
	}
}

// connFingerprint membuat kunci unik untuk koneksi berdasarkan pasangan IP/Port dan protokol.
func connFingerprint(c ConnInfo) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.Protocol)
}