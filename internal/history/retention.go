// Package history mengelola pembersihan data lama secara berkala agar
// ukuran basis data ShadowScanner tetap terkendali. Tabel devices dan settings
// tidak pernah dihapus.
package history

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"shadowscanner/internal/config"
	"shadowscanner/internal/storage"
)

// Retention mengelola tugas pembersihan berkala untuk menghapus riwayat lama
// dari tabel alerts, connections, dan scans.
type Retention struct {
	cfg     *config.Config
	db      *storage.DB
	ticker  *time.Ticker
	stopCh  chan struct{}
	mu      sync.Mutex
	running bool
}

// New menciptakan instance Retention baru dengan konfigurasi dan basis data yang diberikan.
func New(cfg *config.Config, db *storage.DB) *Retention {
	return &Retention{
		cfg:    cfg,
		db:     db,
		ticker: time.NewTicker(5 * time.Minute),
		stopCh: make(chan struct{}),
	}
}

// Start menjalankan goroutine pembersihan berkala setiap 5 menit.
func (r *Retention) Start(ctx context.Context) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()

	go func() {
		for {
			select {
			case <-r.ticker.C:
				r.mu.Lock()
				hours := r.cfg.RetentionHours
				r.mu.Unlock()

				deleted, err := r.db.PurgeOldData(hours)
				if err != nil {
					slog.Error("gagal membersihkan data lama", "error", err)
				} else if deleted > 0 {
					slog.Info("pembersihan data lama selesai", "baris_dihapus", deleted, "retention_hours", hours)
				}

			case <-r.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop menghentikan goroutine pembersihan berkala secara bersih.
func (r *Retention) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return
	}
	r.running = false
	r.ticker.Stop()
	close(r.stopCh)
}

// SetHours memperbarui durasi retensi dalam jam (1-720 jam), menyimpannya
// ke tabel settings, dan memperbarui konfigurasi di memori.
func (r *Retention) SetHours(ctx context.Context, hours int) error {
	if hours < 1 || hours > 720 {
		return fmt.Errorf("durasi retensi harus antara 1 sampai 720 jam, bukan %d", hours)
	}

	r.mu.Lock()
	r.cfg.RetentionHours = hours
	r.mu.Unlock()

	if err := r.db.SetSetting("retention_hours", strconv.Itoa(hours)); err != nil {
		return fmt.Errorf("gagal menyimpan pengaturan retensi ke database: %w", err)
	}

	slog.Info("durasi retensi berhasil diperbarui", "hours", hours)
	return nil
}