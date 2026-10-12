// Package api menyediakan server HTTP lokal ShadowScanner yang melayani
// UI placeholder dan seluruh endpoint API JSON. Semua endpoint terikat
// hanya pada 127.0.0.1.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"shadowscanner/internal/alert"
	"shadowscanner/internal/config"
	"shadowscanner/internal/scanner"
	"shadowscanner/internal/storage"
)

// Server adalah server HTTP lokal ShadowScanner.
type Server struct {
	cfg        *config.Config
	db         *storage.DB
	hub        *SSEHub
	engine     *alert.Engine
	scanner    *scanner.Discovery
	srv        *http.Server
	scanMu     sync.Mutex
	scanCancel context.CancelFunc
	scanning   bool
}

// New menciptakan instance Server baru.
func New(cfg *config.Config, db *storage.DB, hub *SSEHub, engine *alert.Engine, disco *scanner.Discovery) *Server {
	return &Server{
		cfg:     cfg,
		db:      db,
		hub:     hub,
		engine:  engine,
		scanner: disco,
	}
}

// Start memulai server HTTP pada 127.0.0.1:<Port>.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", s.cfg.Port),
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("ShadowScanner berjalan", "url", fmt.Sprintf("http://127.0.0.1:%d", s.cfg.Port))

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// Shutdown menghentikan server HTTP dengan grace period 5 detik.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("menghentikan server HTTP...")
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(shutdownCtx)
}

// loggingMiddleware mencatat setiap permintaan di level debug.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}