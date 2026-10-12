// Package main adalah titik masuk (entry point) aplikasi ShadowScanner.
// Tugas utamanya sangat tipis: memuat konfigurasi, memulai database,
// dan menjalankan server HTTP lokal lengkap dengan engine peringatan,
// SSE hub, serta pembersih riwayat otomatis.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"shadowscanner/internal/alert"
	"shadowscanner/internal/api"
	"shadowscanner/internal/config"
	"shadowscanner/internal/history"
	"shadowscanner/internal/local"
	"shadowscanner/internal/scanner"
	"shadowscanner/internal/storage"
)

func main() {
	ctx := context.Background()

	// 1. Muat konfigurasi dari .env (dan env vars / default jika tidak ada).
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gagal memuat konfigurasi: %v\n", err)
		os.Exit(1)
	}

	// Siapkan logger terstruktur (slog) sesuai level dari .env.
	level, err := slogLevel(cfg.LogLevel)
	if err != nil {
		slog.Warn("level log tidak dikenali, menggunakan default", "suggested_level", "info")
		level = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))

	// 2. Inisialisasi database SQLite (termasuk migrasi tabel).
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		slog.Error("Gagal membuka database", "path", cfg.DBPath, "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		slog.Error("Gagal menjalankan migrasi database", "error", err)
		os.Exit(1)
	}
	slog.Debug("Database terbuka dan tabel siap", "path", cfg.DBPath)

	// 3. Inisialisasi komponen Session 2 & 3 (Scanner, SSE Hub, Alert Engine, Retention Manager, Watcher).
	hub := api.NewSSEHub()
	alertEngine := alert.NewEngine(db)
	alertEngine.SetBroadcaster(hub)

	retentionManager := history.New(cfg, db)
	retentionManager.Start(ctx)
	defer retentionManager.Stop()

	// Inisialisasi pemindai subnet lokal pasif
	disco, err := scanner.NewDiscovery(cfg)
	if err != nil {
		slog.Warn("gagal menginisialisasi modul discovery", "error", err)
	}

	// Inisialisasi pemantau koneksi aktif lokal
	watcher, err := local.NewWatcher(cfg, db)
	if err == nil {
		watcher.SetBroadcaster(hub)
		if err := watcher.Start(ctx); err != nil {
			slog.Debug("tidak dapat memulai pemantau koneksi aktif", "error", err)
		} else {
			defer func() { _ = watcher.Stop() }()
		}
	}

	// 4. Bangun server API lengkap.
	server := api.New(cfg, db, hub, alertEngine, disco)

	// 5. Jalankan server di background sambil menunggu sinyal shutdown.
	errCh := make(chan error, 1)
	go func() {
		if e := server.Start(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server gagal: %w", e)
		}
	}()

	// 6. Buka browser secara otomatis (hanya Windows/Linux, opsional).
	go func() {
		url := fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)
		if err := openBrowser(url); err != nil {
			slog.Debug("tidak dapat membuka browser otomatis", "url", url, "error", err)
		}
	}()

	// 7. Tunggu SIGINT/SIGTERM, lalu shutdown dengan grace period.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
		slog.Info("menerima sinyal shutdown; menutup server ...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := server.Shutdown(shutdownCtx); e != nil {
			slog.Warn("shutdown server tidak sempurna", "error", e)
		}
	case err := <-errCh:
		slog.Error("server berhenti karena error", "error", err)
		os.Exit(1)
	}

	slog.Info("ShadowScanner berhenti")
}

// openBrowser mencoba membuka URL default di browser pengguna secara otomatis.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return runCmd("rundll32.exe", "url.dll,FileProtocolHandler", url)
	case "darwin":
		return nil
	default:
		return runCmd("xdg-open", url)
	}
}

// runCmd menjalankan perintah eksternal dengan aman.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// slogLevel menerjemahkan string level dari .env menjadi level slog yang sesuai.
func slogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("level log tidak dikenal: %s", s)
	}
}