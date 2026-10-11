// Package api menyediakan Server-Sent Events (SSE) hub untuk
// pembaruan real-time ke UI tanpa polling berlebihan.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// SSEHub mengelola daftar pelanggan (subscribers) dan menyiarkan
// peristiwa ke semua pelanggan yang terhubung.
type SSEHub struct {
	mu          sync.RWMutex
	subscribers map[chan string]struct{}
}

// NewSSEHub menciptakan instance SSEHub baru.
func NewSSEHub() *SSEHub {
	return &SSEHub{
		subscribers: make(map[chan string]struct{}),
	}
}

// Broadcast mengirimkan peristiwa ke semua pelanggan yang terhubung.
// event adalah nama peristiwa (mis. "alert", "connection", "device").
// data adalah struktur yang akan di-serialize ke JSON.
func (h *SSEHub) Broadcast(event string, data interface{}) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	jsonData, err := json.Marshal(data)
	if err != nil {
		slog.Error("gagal marshal SSE data", "error", err)
		return
	}

	// Format SSE: event: <name>\ndata: <json>\n\n
	message := fmt.Sprintf("event: %s\ndata: %s\n\n", event, jsonData)

	for ch := range h.subscribers {
		select {
		case ch <- message:
			// Terkirim
		default:
			// Channel penuh: drop event untuk mencegah blocking hub
			// Pelanggan lambat akan kehilangan event ini
		}
	}
}

// ServeHTTP menangani koneksi SSE masuk dari klien.
func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set header SSE
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*") // Local only anyway

	// Buat channel untuk pelanggan ini
	ch := make(chan string, 256)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()

	// Pastikan cleanup saat koneksi ditutup
	ctx := r.Context()
	defer func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		h.mu.Unlock()
		close(ch)
	}()

	// Kirim heartbeat setiap 15 detik untuk menjaga koneksi hidup
	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	// Flusher diperlukan untuk memaksa penulisan ke klien
	flusher, ok := w.(http.Flusher)
	if !ok {
		slog.Error("http.ResponseWriter tidak mendukung Flushing")
		http.Error(w, "Streaming tidak didukung", http.StatusInternalServerError)
		return
	}

	// Loop utama: kirim pesan ke klien
	for {
		select {
		case msg := <-ch:
			// Kirim pesan event ke klien
			if _, err := fmt.Fprint(w, msg); err != nil {
				slog.Debug("klien SSE terputus", "error", err)
				return
			}
			flusher.Flush()

		case <-heartbeatTicker.C:
			// Kirim komentar heartbeat untuk menjaga koneksi hidup
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()

		case <-ctx.Done():
			// Klien menutup koneksi atau context dibatalkan
			return
		}
	}
}