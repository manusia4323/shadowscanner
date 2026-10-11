// Package api berisi handler untuk semua rute HTTP ShadowScanner.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"shadowscanner/internal/alert"
	"shadowscanner/internal/config"
	"shadowscanner/internal/history"
	"shadowscanner/internal/local"
	"shadowscanner/internal/storage"
)

// ----- Helper types for JSON responses -----

type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Code    string      `json:"code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("gagal encode JSON response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg, code string) {
	writeJSON(w, status, apiResponse{Success: false, Error: msg, Code: code})
}

func writeSuccess(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, apiResponse{Success: true, Data: data})
}

// ----- Main handlers -----

// handleIndex melayani halaman UI utama.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Embedded HTML akan disuntikkan di Session 4
	// Untuk sekarang, kembalikan placeholder
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ShadowScanner — Pemeriksa Jaringan</title>
    <meta name="csrf" content="{{CSRF}}">
    <style>
        body { font-family: system-ui; max-width: 800px; margin: 40px auto; padding: 20px; background: #0f1115; color: #e6e8ee; }
        .card { background: #171a21; border: 1px solid #232733; border-radius: 8px; padding: 24px; margin-bottom: 16px; }
        h1 { color: #60a5fa; }
        .status { display: inline-block; padding: 8px 16px; border-radius: 20px; background: #34d399; color: #0f1115; font-weight: 600; }
        .btn { display: inline-block; padding: 12px 24px; background: #60a5fa; color: #0f1115; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .btn:hover { background: #3b82f6; }
    </style>
</head>
<body>
    <div class="card">
        <h1>ShadowScanner</h1>
        <p class="status">Aman — Server berjalan</p>
        <p>Aplikasi ini memeriksa jaringan Anda untuk menemukan aktivitas mencurigakan.</p>
        <button class="btn" onclick="fetch('/api/scan/start', {method:'POST'}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">Pindai Sekarang</button>
    </div>
    <div class="card">
        <h2>Endpoint API</h2>
        <ul>
            <li>GET /api/health — Cek kesehatan server</li>
            <li>GET /api/self — Info perangkat Anda</li>
            <li>GET /api/devices — Perangkat di jaringan</li>
            <li>GET /api/alerts — Peringatan keamanan</li>
            <li>GET /api/connections — Koneksi jaringan aktif</li>
            <li>GET /api/connections/stream — SSE stream koneksi baru</li>
            <li>GET /api/alerts/stream — SSE stream peringatan baru</li>
            <li>GET /api/history — Riwayat pemindaian</li>
            <li>GET /api/recommendations — Rekomendasi keamanan</li>
            <li>POST /api/scan/start — Mulai pemindaian</li>
        </ul>
    </div>
    <script>
        // SSE connection for alerts
        const esAlerts = new EventSource('/api/alerts/stream');
        esAlerts.onmessage = (e) => console.log('Alert:', e.data);
        esAlerts.onerror = () => console.log('SSE alerts disconnected');
    </script>
</body>
</html>`)
}

// handleHealth mengembalikan status kesehatan server.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeSuccess(w, map[string]string{"status": "ok", "service": "shadowscanner"})
}

// handleSelf mengembalikan informasi perangkat pengguna.
func (s *Server) handleSelf(w http.ResponseWriter, r *http.Request) {
	info, err := local.Get(r.Context())
	if err != nil {
		slog.Error("gagal mendapatkan info perangkat", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal mendapatkan info perangkat", "SELF_INFO_FAILED")
		return
	}
	writeSuccess(w, info)
}

// handleDevices mengembalikan daftar perangkat yang terdeteksi.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.db.ListDevices()
	if err != nil {
		slog.Error("gagal mendapatkan daftar perangkat", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal mendapatkan daftar perangkat", "DEVICES_LIST_FAILED")
		return
	}
	writeSuccess(w, devices)
}

// handleAlerts mengembalikan daftar peringatan, dengan filter severity opsional.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	alerts, err := s.db.ListAlerts(severity)
	if err != nil {
		slog.Error("gagal mendapatkan daftar peringatan", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal mendapatkan daftar peringatan", "ALERTS_LIST_FAILED")
		return
	}
	writeSuccess(w, alerts)
}

// handleAcknowledgeAlert menandai peringatan sebagai sudah dibaca.
func (s *Server) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ID peringatan tidak valid", "INVALID_ID")
		return
	}

	if err := s.engine.Acknowledge(r.Context(), id); err != nil {
		slog.Error("gagal mengakui peringatan", "error", err, "id", id)
		writeError(w, http.StatusInternalServerError, "Gagal mengakui peringatan", "ACK_FAILED")
		return
	}

	writeSuccess(w, map[string]string{"status": "acknowledged"})
}

// handleConnections mengembalikan daftar koneksi jaringan.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	conns, err := s.db.ListConnections(limit)
	if err != nil {
		slog.Error("gagal mendapatkan daftar koneksi", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal mendapatkan daftar koneksi", "CONNECTIONS_LIST_FAILED")
		return
	}
	writeSuccess(w, conns)
}

// handleConnectionsStream melayani SSE stream untuk koneksi baru.
func (s *Server) handleConnectionsStream(w http.ResponseWriter, r *http.Request) {
	s.hub.ServeHTTP(w, r)
}

// handleAlertsStream melayani SSE stream untuk peringatan baru.
func (s *Server) handleAlertsStream(w http.ResponseWriter, r *http.Request) {
	s.hub.ServeHTTP(w, r)
}

// handleHistory mengembalikan riwayat pemindaian.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	scans, err := s.db.ListScans(limit)
	if err != nil {
		slog.Error("gagal mendapatkan riwayat pemindaian", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal mendapatkan riwayat pemindaian", "HISTORY_LIST_FAILED")
		return
	}
	writeSuccess(w, scans)
}

// handleSetRetention mengubah durasi penyimpanan data.
func (s *Server) handleSetRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours int `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Format JSON tidak valid", "INVALID_JSON")
		return
	}

	// Validasi range
	if req.Hours < 1 || req.Hours > 720 {
		writeError(w, http.StatusBadRequest, "Retention hours harus antara 1 dan 720", "INVALID_RETENTION")
		return
	}

	// Buat instance Retention sementara untuk mengubah pengaturan
	retention := history.New(s.cfg, s.db)
	if err := retention.SetHours(r.Context(), req.Hours); err != nil {
		slog.Error("gagal mengubah retention", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal mengubah durasi penyimpanan", "RETENTION_SET_FAILED")
		return
	}

	writeSuccess(w, map[string]interface{}{
		"retention_hours": req.Hours,
		"message":         "Durasi penyimpanan diperbarui",
	})
}

// handleRecommendations mengembalikan rekomendasi keamanan.
func (s *Server) handleRecommendations(w http.ResponseWriter, r *http.Request) {
	devices, err := s.db.ListDevices()
	if err != nil {
		slog.Error("gagal mendapatkan perangkat untuk rekomendasi", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal memproses rekomendasi", "RECS_FAILED")
		return
	}

	alerts, err := s.db.ListAlerts("")
	if err != nil {
		slog.Error("gagal mendapatkan peringatan untuk rekomendasi", "error", err)
		writeError(w, http.StatusInternalServerError, "Gagal memproses rekomendasi", "RECS_FAILED")
		return
	}

	recs := alert.Generate(alerts, devices)
	writeSuccess(w, recs)
}

// handleScanStart memulai pemindaian jaringan baru.
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	// TODO: Implementasi pemindaian penuh akan mengintegrasikan
	// discovery, ports, fingerprint, distance, isp, dan alert engine.
	// Untuk Session 3, kembalikan respons placeholder.
	writeSuccess(w, map[string]string{
		"status":  "started",
		"message": "Pemindaian dimulai (implementasi lengkap di Session 4)",
	})
}

// handleScanStop menghentikan pemindaian yang sedang berlangsung.
func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	// TODO: Implementasi menghentikan pemindaian yang berjalan
	writeSuccess(w, map[string]string{
		"status":  "stopped",
		"message": "Pemindaian dihentikan (implementasi lengkap di Session 4)",
	})
}

// handleSettings mengembalikan pengaturan saat ini.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	// Kunci pengaturan yang dikenal
	keys := []string{"retention_hours", "warning_mode", "scan_interval"}
	settings := make(map[string]string)

	for _, key := range keys {
		val, err := s.db.GetSetting(key)
		if err == nil {
			settings[key] = val
		}
	}

	writeSuccess(w, settings)
}

// handleUpdateSettings memperbarui pengaturan.
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Format JSON tidak valid", "INVALID_JSON")
		return
	}

	allowed := map[string]bool{
		"retention_hours":  true,
		"warning_mode":     true,
		"scan_interval":    true,
		"max_devices":      true,
		"log_level":        true,
		"network_interface": true,
		"capture_device":   true,
		"browser_launch":   true,
	}

	for key, val := range req {
		if !allowed[key] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("Pengaturan %s tidak diizinkan diubah", key), "SETTING_NOT_ALLOWED")
			return
		}
		if err := s.db.SetSetting(key, val); err != nil {
			slog.Error("gagal memperbarui pengaturan", "key", key, "error", err)
			writeError(w, http.StatusInternalServerError, "Gagal memperbarui pengaturan", "SETTING_UPDATE_FAILED")
			return
		}
	}

	writeSuccess(w, map[string]string{"status": "updated"})
}