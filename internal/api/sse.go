// Package api menyediakan SSEHub untuk mengelola dan menyiarkan
// event real-time ke klien melalui Server-Sent Events (SSE).
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// SSEHub mengelola langganan klien SSE dan menyiarkan pesan ke semua klien terhubung.
type SSEHub struct {
	mu          sync.Mutex
	subscribers map[chan string]struct{}
}

// NewSSEHub menciptakan instance SSEHub baru.
func NewSSEHub() *SSEHub {
	return &SSEHub{
		subscribers: make(map[chan string]struct{}),
	}
}

// Broadcast memformat event dan data menjadi format SSE standar lalu mengirimkannya
// ke seluruh klien yang sedang berlangganan.
func (h *SSEHub) Broadcast(event string, data any) {
	payload, err := json.Marshal(data)
	if err != nil {
		slog.Error("gagal serialisasi data SSE", "error", err)
		return
	}

	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", event, string(payload))

	h.mu.Lock()
	defer h.mu.Unlock()

	for ch := range h.subscribers {
		select {
		case ch <- msg:
		default:
			// Klien lambat, abaikan agar tidak memblokir
		}
	}
}

// ServeHTTP menangani koneksi HTTP untuk endpoint SSE.
func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming tidak didukung pada server ini", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 10)

	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.subscribers, ch)
		close(ch)
		h.mu.Unlock()
	}()

	// Kirim komentar awal agar koneksi langsung terbuka
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case msg := <-ch:
			_, _ = fmt.Fprint(w, msg)
			flusher.Flush()
		}
	}
}