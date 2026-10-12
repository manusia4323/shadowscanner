// Package ui menyediakan pengujian untuk aset tertanam dan handler HTTP statis.
package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexHTML(t *testing.T) {
	html, err := IndexHTML()
	if err != nil {
		t.Fatalf("IndexHTML failed: %v", err)
	}
	if len(html) == 0 {
		t.Fatalf("expected non-empty index.html")
	}
	if !strings.Contains(string(html), "ShadowScanner") {
		t.Errorf("expected index.html to contain 'ShadowScanner'")
	}
	if !strings.Contains(string(html), "<!DOCTYPE html>") {
		t.Errorf("expected index.html to start with <!DOCTYPE html>")
	}
}

func TestHandlerServesAssets(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Fatalf("expected non-nil handler")
	}

	// Handler() menempatkan file dari sub-direktori assets-nya ke root HTTP.
	// Setiap file diakses dari root URL tanpa "/assets/" prefix (StripPrefix sudah dihapus).
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// 1. /index.html — halaman utama HTML
	resp, err := http.Get(srv.URL + "/index.html")
	if err != nil {
		t.Fatalf("client.Get /index.html failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for /index.html, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. /css/style.css — stylesheet
	resp, err = http.Get(srv.URL + "/css/style.css")
	if err != nil {
		t.Fatalf("client.Get /css/style.css failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for /css/style.css, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 3. /js/*.js — semua file JS
	for _, jsFile := range []string{
		"/js/app.js",
		"/js/api.js",
		"/js/i18n.js",
		"/js/alerts.js",
		"/js/graph.js",
		"/js/floorplan.js",
	} {
		resp, err = http.Get(srv.URL + jsFile)
		if err != nil {
			t.Fatalf("client.Get %s failed: %v", jsFile, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for %s, got %d", jsFile, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestHandler404ForMissingAsset(t *testing.T) {
	handler := Handler()

	req := httptest.NewRequest(http.MethodGet, "/nonexistent/file.txt", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing asset, got %d", w.Code)
	}
}