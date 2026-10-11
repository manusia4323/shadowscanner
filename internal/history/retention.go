// Package retention mengelola pemeliharaan ukuran basis data ShadowScanner
// dengan menghapus baris lama dari tabel alerts, connections, dan scans
// secara berkala. Tabel devices dan settings TIDAK PERNAH dihapus.
package history

import (
	"context"
	"time"

	"shadowscanner/internal/config"
	"shadowscanner/internal/storage"
)

// Retention mengelola pembersihan data lama secara berkala agar
// basis data ShadowScanner tetap kecil.
type Retention struct {
	cfg     *config.Config
	db      *storage.DB
	ticker  *time.Ticker
	stopCh  chan struct{}
}

// New menciptakan instance Retention yang menyimpan data selama
// cfg.RetentionHours. Pengaturan dapat diubah setelah pembuatan.
func New(cfg *config.Config, db *storage.DB) *Retention {
	return &Retention{
		cfg:    cfg,
		db:     db,
		ticker: time.NewTicker(5 * time.Minute),
		stopCh: make(chan struct{}),
	}
}

// Start memulai goroutine yang setiap 5 menit menghapus baris lama
// dari basis data. Tunggu goroutine ini selesai dengan Stop() sebelum
// aplikasi berhenti.
func (r *Retention) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-r.ticker.C:
				total, err := r.db.PurgeOldData(r.cfg.RetentionHours)
				if err != nil {
					slog.Error("gagal menghapus data lama", "error", err)
					continue
				}
				if total > 0 {
					slog.Info("data lama dihapus", "rows", total)
				}
			case <-r.stopCh:
				r.ticker.Stop()
				return
			case <-ctx.Done():
				r.ticker.Stop()
				return
			}
		}
	}()
}

// Stop menghentikan pemeliharaan basis data dan membersihkan
// goroutine yang berjalan.
func (r *Retention) Stop() {
	close(r.stopCh)
}

// SetHours mengubah durasi penyimpanan data. Validasi dilakukan
// oleh cfg (1-720 jam). Nilai ini diperbarui di basis data dan di
// memori agar setiap penghapusan berikutnya menggunakan nilai baru.
func (r *Retention) SetHours(ctx context.Context, hours int) error {
	// Validasi range
	if hours < 1 || hours > 720 {
		return fmt.Errorf("retention hours harus antara 1 dan 720, bukan %d", hours)
	}

	r.cfg.RetentionHours = hours

	// Simpan ke basis data
	return r.db.SetSetting(ctx, "retention_hours", strconv.Itoa(hours))
}