// Package api menyediakan fungsi dan rute penanganan HTTP untuk ShadowScanner.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"shadowscanner/internal/alert"
	"shadowscanner/internal/local"
	"shadowscanner/internal/scanner"
	"shadowscanner/internal/storage"
	"shadowscanner/internal/ui"
)

// registerRoutes mendaftarkan seluruh endpoint API ke ServeMux.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Aset statis UI (CSS, JS) di bawah /assets/
	mux.Handle("/assets/", http.StripPrefix("/assets/", ui.Handler()))

	// Halaman utama UI tertanam (index.html)
	mux.HandleFunc("/", s.handleIndex)

	// API Endpoints
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/self", s.handleSelf)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/acknowledge", s.handleAcknowledgeAlert)
	mux.HandleFunc("/api/connections", s.handleConnections)
	mux.HandleFunc("/api/connections/stream", s.handleConnectionsStream)
	mux.HandleFunc("/api/alerts/stream", s.handleAlertsStream)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/retention", s.handleSetRetention)
	mux.HandleFunc("/api/recommendations", s.handleRecommendations)
	mux.HandleFunc("/api/scan/start", s.handleScanStart)
	mux.HandleFunc("/api/scan/stop", s.handleScanStop)
	mux.HandleFunc("/api/settings", s.handleSettings)
}

// handleIndex menyajikan halaman utama antarmuka web ShadowScanner dari
// aset statis yang tertanam (embedded index.html).
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html, err := ui.IndexHTML()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "gagal memuat antarmuka")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(html)
}

// handleHealth mengembalikan status kesehatan server.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// handleSelf mengembalikan informasi perangkat lokal dan antarmuka jaringan.
func (s *Server) handleSelf(w http.ResponseWriter, r *http.Request) {
	info, err := local.Get(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleDevices mengembalikan daftar perangkat yang terdeteksi di jaringan.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.db.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

// handleAlerts mengembalikan daftar peringatan keamanan.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.db.ListAlerts("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// handleAcknowledgeAlert menandai peringatan sebagai sudah dibaca.
func (s *Server) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Parameter id tidak valid")
		return
	}

	if err := s.engine.Acknowledge(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleConnections mengembalikan daftar koneksi jaringan aktif.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := s.db.ListConnections(100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

// handleConnectionsStream menyediakan SSE untuk aliran koneksi jaringan real-time.
func (s *Server) handleConnectionsStream(w http.ResponseWriter, r *http.Request) {
	s.hub.ServeHTTP(w, r)
}

// handleAlertsStream menyediakan SSE untuk aliran peringatan keamanan real-time.
func (s *Server) handleAlertsStream(w http.ResponseWriter, r *http.Request) {
	s.hub.ServeHTTP(w, r)
}

// handleHistory mengembalikan ringkasan riwayat pemindaian.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.ListScans(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// handleSetRetention memperbarui durasi retensi data.
func (s *Server) handleSetRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}
	hoursStr := r.URL.Query().Get("hours")
	hours, err := strconv.Atoi(hoursStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Parameter hours tidak valid")
		return
	}
	if hours < 1 || hours > 720 {
		writeError(w, http.StatusBadRequest, "Durasi retensi harus antara 1 sampai 720 jam")
		return
	}
	if err := s.db.SetSetting("retention_hours", strconv.Itoa(hours)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "retention_hours": hours})
}

// handleRecommendations mengembalikan saran rekomendasi tindakan keamanan.
func (s *Server) handleRecommendations(w http.ResponseWriter, r *http.Request) {
	dbAlerts, err := s.db.ListAlerts("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var alerts []alert.Alert
	for _, a := range dbAlerts {
		alerts = append(alerts, alert.Alert{
			ID:          a.ID,
			Timestamp:   a.Timestamp,
			Severity:    alert.Severity(a.Severity),
			Category:    a.Category,
			Title:       a.Title,
			Explanation: a.Explanation,
			Action:      a.Action,
			Technical:   a.Technical,
			DeviceMAC:   a.DeviceMAC,
		})
	}

	devices, err := s.db.ListDevices()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	recs := alert.Generate(alerts, devices)
	writeJSON(w, http.StatusOK, recs)
}

// handleScanStart memulai pemindaian manual.
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}

	s.scanMu.Lock()
	if s.scanning {
		s.scanMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"message": "pemindaian sedang berlangsung",
		})
		return
	}
	s.scanning = true
	scanCtx, cancel := context.WithCancel(context.Background())
	s.scanCancel = cancel
	s.scanMu.Unlock()

	s.hub.Broadcast("scan", map[string]any{"status": "started", "timestamp": time.Now()})

	go func() {
		defer func() {
			s.scanMu.Lock()
			s.scanning = false
			s.scanCancel = nil
			s.scanMu.Unlock()
		}()

		startedAt := time.Now()
		if s.scanner == nil {
			slog.Warn("komponen scanner belum diinisialisasi")
			s.hub.Broadcast("scan", map[string]any{"status": "error", "message": "scanner belum diinisialisasi"})
			return
		}

		devices, err := s.scanner.Scan(scanCtx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				slog.Info("pemindaian dibatalkan pengguna")
				s.hub.Broadcast("scan", map[string]any{"status": "stopped", "message": "pemindaian dibatalkan"})
			} else {
				slog.Error("pemindaian gagal", "error", err)
				s.hub.Broadcast("scan", map[string]any{"status": "error", "message": err.Error()})
			}
			return
		}

		for _, dev := range devices {
			if scanCtx.Err() != nil {
				break
			}

			// Periksa port terbuka
			ports, _ := scanner.CheckPorts(scanCtx, dev.IP, 300*time.Millisecond)

			// Tebak tipe perangkat
			fp := scanner.Guess(dev, ports)

			// Estimasi jarak fisik kasar
			dist := scanner.Estimate(scanCtx, dev)

			now := time.Now()
			storageDev := &storage.Device{
				MAC:                dev.MAC,
				IP:                 dev.IP,
				Hostname:           dev.Hostname,
				Vendor:             fp.Vendor,
				DeviceType:         fp.DeviceType,
				FirstSeen:          now,
				LastSeen:           now,
				Confidence:         fp.Confidence,
				DistanceEstimate:   dist.Meters,
				DistanceConfidence: dist.Confidence,
			}

			_ = s.db.UpsertDevice(storageDev)
			s.hub.Broadcast("device", storageDev)
		}

		// Simpan ringkasan ke riwayat scans
		_, _ = s.db.InsertScan(&storage.Scan{
			StartedAt:   startedAt,
			FinishedAt:  time.Now(),
			DeviceCount: len(devices),
			AlertCount:  0,
		})

		s.hub.Broadcast("scan", map[string]any{
			"status":        "completed",
			"devices_found": len(devices),
			"finished_at":   time.Now(),
		})
	}()

	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "pemindaian dimulai"})
}

// handleScanStop menghentikan pemindaian aktif.
func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}

	s.scanMu.Lock()
	if !s.scanning || s.scanCancel == nil {
		s.scanMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "tidak ada pemindaian aktif",
		})
		return
	}
	s.scanCancel()
	s.scanMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "pemindaian dihentikan"})
}

// handleSettings membaca atau memperbarui pengaturan aplikasi.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Format JSON tidak valid")
			return
		}
		for k, v := range req {
			_ = s.db.SetSetting(k, v)
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
		return
	}

	retStr, err := s.db.GetSetting("retention_hours")
	retHours := 8
	if err == nil && retStr != "" {
		if h, parseErr := strconv.Atoi(retStr); parseErr == nil {
			retHours = h
		}
	}

	warnStr, _ := s.db.GetSetting("warning_mode")
	warningMode := s.cfg.WarningMode
	if warnStr == "true" {
		warningMode = true
	} else if warnStr == "false" {
		warningMode = false
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"port":            s.cfg.Port,
		"retention_hours": retHours,
		"warning_mode":    warningMode,
	})
}

// Helper untuk mengirim respons JSON
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// Helper untuk mengirim pesan error JSON
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message})
}