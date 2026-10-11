// Package main adalah titik masuk (entry point) aplikasi ShadowScanner.
// Tugas utamanya sangat tipis: memuat konfigurasi, memulai database,
// dan menjalankan server HTTP lokal sederhana. Semua logika bisnis ada di
// package internal/ lainnya.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"shadowscanner/internal/config"
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
		// Jangan panic: turunkan level ke "info" secara aman.
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

	// 3. Bangun server HTTP sederhana.
	srv := newServer(cfg, slog.Default())

	// 4. Jalankan server di background sambil menunggu sinyal shutdown.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("Memulai server lokal", "addr", fmt.Sprintf("127.0.0.1:%d", cfg.Port))
		if e := srv.Start(ctx); e != nil && !errors.Is(e, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server gagal: %w", e)
		}
	}()

	// 5. Buka browser secara otomatis (hanya Windows/Linux, opsional).
	go func() {
		url := fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)
		if err := openBrowser(url); err != nil {
			// Tidak kritis: log saja, jangan ganggu proses lain.
			slog.Debug("tidak dapat membuka browser otomatis", "url", url, "error", err)
		}
	}()

	// 6. Tunggu SIGINT/SIGTERM, lalu shutdown dengan grace period.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
		slog.Info("menerima sinyal shutdown; menutup server ...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := srv.Shutdown(shutdownCtx); e != nil {
			slog.Warn("shutdown server tidak sempurna", "error", e)
		}
	case err := <-errCh:
		slog.Error("server berhenti karena error", "error", err)
		os.Exit(1)
	}

	slog.Info("ShadowScanner berhenti")
}

// newServer membentuk server HTTP lokal yang mengikat 127.0.0.1 saja dan
// melayani halaman placeholder untuk Session 1.
func newServer(cfg *config.Config, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log setiap permintaan pada level debug (termasuk health check).
			logger.Debug("permintaan masuk",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ShadowScanner is starting...")
		}),
	}
}

// openBrowser mencoba membuka URL default di browser pengguna secara
// otomatis. Hanya dijalankan di Windows dan Linux; di macOS dan sistem lain
// fungsi ini tidak melakukan apa-apa (bukan error).
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return execWindows(url)
	case "darwin":
		// macOS: dapat dijalankan nanti, jangan paksa saat ini.
		return nil
	default:
		// Linux dan lain-lain.
		return execLinux(url)
	}
}

// execWindows membuka URL lewat rundll32 (Windows). Argumen dipisah agar
// URL dengan spasi atau tanda kutip tetap aman.
func execWindows(url string) error {
	// rundll32.exe url.dll,FileProtocolHandler <url>
	return exec("rundll32.exe", []string{"url.dll,FileProtocolHandler", url})
}

// execLinux membuka URL lewat xdg-open (umum di Linux desktop).
func execLinux(url string) error {
	return exec("xdg-open", []string{url})
}

// exec menjalankan perintah dengan os/exec tanpa menampilkan output, lalu
// membalikkan error jika proses gagal.
func exec(name string, args []string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run() // error non-nil bila proses tidak berjalan sukses
}

// slogLevel menerjemahkan string level dari .env menjadi level slog yang
// sesuai. Level yang tidak dikenali ditolak secara eksplisit agar aplikasi
// tidak diam-diam menggunakan pengaturan yang salah.
func slogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("level log tidak valid: %q (pilih debug/info/warn/error)", s)
	}
}
