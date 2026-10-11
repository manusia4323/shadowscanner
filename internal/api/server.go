// Package api menyediakan server HTTP lokal yang melayani UI dan JSON API
// untuk ShadowScanner. Semua endpoint hanya terikat ke 127.0.0.1.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"shadowscanner/internal/alert"
	"shadowscanner/internal/config"
	"shadowscanner/internal/local"
	"shadowscanner/internal/storage"
)

// Server adalah server HTTP lokal ShadowScanner.
type Server struct {
	cfg    *config.Config
	db     *storage.DB
	hub    *SSEHub
	engine *alert.Engine
	srv    *http.Server
}

// New menciptakan instance Server baru dengan konfigurasi, basis data,
// hub SSE, dan engine alert yang diberikan.
func New(cfg *config.Config, db *storage.DB, hub *SSEHub, engine *alert.Engine) *Server {
	if cfg == nil {
		panic("config is required")
	}
	if db == nil {
		panic("database is required")
	}
	if hub == nil {
		panic("SSE hub is required")
	}
	if engine == nil {
		panic("alert engine is required")
	}
	return &Server{
		cfg:    cfg,
		db:     db,
		hub:    hub,
		engine: engine,
	}
}

// Start memulai server HTTP pada 127.0.0.1:Port.
// Fungsi ini tidak mengembalikan nilai sampai server dihentikan.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", s.cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("Memulai server HTTP", "addr", s.srv.Addr)

	// Jalankan server dalam goroutine untuk mengembalikan kontrol
	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Tunggu sinyal berhenti atau error
	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// Shutdown menghentikan server HTTP dengan grace period 5 detik.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("Menghentikan server HTTP...")

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := s.srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("Shutdown server tidak sempurna", "error", err)
		return err
	}

	slog.Info("Server HTTP dihentikan")
	return nil
}

// RegisterRoutes mendaftarkan semua rute HTTP ke ServeMux yang diberikan.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Middleware logging untuk setiap request
	logged := s.logMiddleware(mux)

	// Halaman utama (UI)
	mux.HandleFunc("GET /", s.handleIndex)

	// API routes
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/self", s.handleSelf)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/alerts", s.handleAlerts)
	mux.HandleFunc("POST /api/alerts/{id}/ack", s.handleAcknowledgeAlert)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("GET /api/connections/stream", s.handleConnectionsStream)
	mux.HandleFunc("GET /api/alerts/stream", s.handleAlertsStream)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("POST /api/history/retention", s.handleSetRetention)
	mux.HandleFunc("GET /api/recommendations", s.handleRecommendations)
	mux.HandleFunc("POST /api/scan/start", s.handleScanStart)
	mux.HandleFunc("POST /api/scan/stop", s.handleScanStop)
	mux.HandleFunc("GET /api/settings", s.handleSettings)
	mux.HandleFunc("POST /api/settings", s.handleUpdateSettings)

	// SSE endpoints
	mux.Handle("GET /events", s.hub)
}

// logMiddleware membungkus handler dengan logging debug.
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", "handled",
			"duration_ms", time.Since(start).Milliseconds())
	})
}