package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shadowscanner/internal/alert"
	"shadowscanner/internal/config"
	"shadowscanner/internal/scanner"
	"shadowscanner/internal/storage"
)

func setupTestServer(t *testing.T) (*Server, *storage.DB) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	cfg := &config.Config{
		Port:            8787,
		RetentionHours:  8,
		ScanIntervalSec: 60,
		LogLevel:        "info",
		MaxDevices:      256,
		DBPath:          dbPath,
	}

	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}

	hub := NewSSEHub()
	engine := alert.NewEngine(db)
	engine.SetBroadcaster(hub)

	disco, err := scanner.NewDiscovery(cfg)
	if err != nil {
		t.Fatalf("NewDiscovery failed: %v", err)
	}

	server := New(cfg, db, hub, engine, disco)
	return server, db
}

func TestAPIEndpoints(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	mux := http.NewServeMux()
	server.registerRoutes(mux)

	// 1. GET /api/health
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/health expected 200, got %d", w.Code)
	}

	// 2. GET /api/self
	req = httptest.NewRequest(http.MethodGet, "/api/self", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/self expected 200, got %d", w.Code)
	}

	// 3. GET /api/devices
	req = httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/devices expected 200, got %d", w.Code)
	}

	// 4. GET /api/alerts
	req = httptest.NewRequest(http.MethodGet, "/api/alerts", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/alerts expected 200, got %d", w.Code)
	}

	// 5. GET /api/connections
	req = httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/connections expected 200, got %d", w.Code)
	}

	// 6. GET /api/history
	req = httptest.NewRequest(http.MethodGet, "/api/history", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/history expected 200, got %d", w.Code)
	}

	// 7. GET /api/recommendations
	req = httptest.NewRequest(http.MethodGet, "/api/recommendations", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/recommendations expected 200, got %d", w.Code)
	}

	// 8. GET & POST /api/settings
	req = httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/settings expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(`{"warning_mode":"true"}`))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("POST /api/settings expected 200, got %d", w.Code)
	}

	// 9. POST /api/scan/start & stop
	req = httptest.NewRequest(http.MethodPost, "/api/scan/start", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("POST /api/scan/start expected 200, got %d", w.Code)
	}

	time.Sleep(50 * time.Millisecond)

	req = httptest.NewRequest(http.MethodPost, "/api/scan/stop", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("POST /api/scan/stop expected 200, got %d", w.Code)
	}
}

func TestSSEStream(t *testing.T) {
	server, db := setupTestServer(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		server.hub.Broadcast("alert", map[string]string{"title": "Test Alert"})
	}()

	server.handleAlertsStream(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "event: alert") {
		t.Errorf("expected SSE body to contain event: alert, got %q", body)
	}
}
