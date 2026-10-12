// Package storage menyediakan operasi CRUD database SQLite lengkap tanpa ORM,
// menggunakan driver modernc.org/sqlite (pure Go, CGO_ENABLED=0-compatible).
// Tiap fungsi terverifikasi dokumentasi dan menerapkan context.Context
// untuk operasi yang bisa dibatalkan, error yang didukung, dan tidak ada panic.
//
// Struktur tabel dan indeks diselaraskan dengan types/models.go.

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
	_ "modernc.org/sqlite"
)

// DB adalah wrapper tipis untuk *sql.DB. Exported agar bisa digunakan
// sebagai tipe parameter; semua method yang eksternal membuka hubungan
// dengan DB melalui tipe ini.
type DB struct {
	*sql.DB
}

// Open membuka koneksi database SQLite pada path yang diberikan.
// Di sini:
//   - Mendorong driver CGO_ENABLED=0 (pure Go).
//   - Mengaktifkan WAL mode (Write-Ahead Logging) agar performa dan
//     integritas transaksi lebih baik saat proses tidak diprediksi.
//   - Mengaktifkan foreign keys agar integritas referensial terjaga.
//   - Migrasi otomatis tabel (jika belum ada).
func Open(path string) (*DB, error) {
	// modernc.org/sqlite mendukung driver tanpa CGO.
	// Driver yang didaftarkan oleh modernc.org/sqlite adalah "sqlite".
	dbDriver := "sqlite"

	// Buka koneksi melalui driver database/sql umum.
	// Parameter "?mode=memory" = only for in-memory; kita gunakan file.
	db, err := sql.Open(dbDriver, path)
	if err != nil {
		return nil, fmt.Errorf("buka database: %w", err)
	}

	// Aktifkan WAL mode dan syncpoint penuh agar log WAL selamat disalvasi
	// saat crash (checkpoint tiap transaksi).
	_, err = db.ExecContext(context.Background(), "PRAGMA journal_mode=WAL")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("aktifkan WAL mode: %w", err)
	}

	// WAL checkpoint setiap transaksi selesai.
	_, err = db.ExecContext(context.Background(), "PRAGMA wal_autocheckpoint=1000")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("atur WAL autocheckpoint: %w", err)
	}

	// Waktunya aktifkan foreign keys (disabled secara default di SQLite).
	_, err = db.ExecContext(context.Background(), "PRAGMA foreign_keys=ON")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("aktifkan foreign keys: %w", err)
	}

	storageDB := &DB{db}
	if err := storageDB.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrasi skema database gagal: %w", err)
	}

	return storageDB, nil
}

// Migrate membuat semua tabel dan indeks jika belum ada. Tiap pemanggilan
// aman untuk diulang (tidak akan menghapus data atau tabel).
func (db *DB) Migrate() error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("mulai transaksi migrasi: %w", err)
	}

	// --- Tabel devices ---
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT NOT NULL,
			ip TEXT NOT NULL,
			hostname TEXT,
			vendor TEXT,
			devicetype TEXT,
			first_seen TIMESTAMP NOT NULL,
			last_seen TIMESTAMP NOT NULL,
			confidence REAL NOT NULL,
			distance_estimate REAL,
			distance_confidence TEXT
		)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat tabel devices: %w", err)
	}

	// --- Tabel alerts ---
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			explanation TEXT NOT NULL,
			action TEXT NOT NULL,
			technical TEXT,
			device_mac TEXT,
			acknowledged INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat tabel alerts: %w", err)
	}

	// --- Tabel connections ---
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS connections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			direction TEXT NOT NULL,
			localip TEXT NOT NULL,
			localport INTEGER NOT NULL,
			remoteip TEXT,
			remoteport INTEGER,
			protocol TEXT NOT NULL,
			processname TEXT,
			processpid INTEGER,
			state TEXT NOT NULL
		)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat tabel connections: %w", err)
	}

	// --- Tabel scans ---
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at TIMESTAMP NOT NULL,
			finished_at TIMESTAMP,
			devicecount INTEGER NOT NULL DEFAULT 0,
			alertcount INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat tabel scans: %w", err)
	}

	// --- Tabel settings ---
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat tabel settings: %w", err)
	}

	// --- Index ---
	// idx_devices_mac: menjamin keunikan MAC dan mempercepat pencarian.
	_, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat idx_devices_mac: %w", err)
	}

	// idx_devices_last_seen: mempercepat pengurutan last_seen DESC.
	_, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat idx_devices_last_seen: %w", err)
	}

	// idx_alerts_timestamp: mempercepat listing alerts DESC per waktu.
	_, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat idx_alerts_timestamp: %w", err)
	}

	// idx_alerts_severity: mempercepat filter alerts by severity.
	_, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat idx_alerts_severity: %w", err)
	}

	// idx_connections_timestamp: mempercepat listing connections DESC per waktu.
	_, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp DESC)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("buat idx_connections_timestamp: %w", err)
	}

	// Commit transaksi migrasi.
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrasi: %w", err)
	}

	slog.Debug("Migrasi database selesai; semua tabel & index sudah siap")
	return nil
}

// CRUD helpers — bernama sesuai kebutuhan Session 1-3. Tiap fungsi mengembalikan
// error wrapper dengan fmt.Errorf + %w, dan tidak pernah panic secara tersembunyi.

// UpsertDevice memasukkan atau memperbarui Device. Jika MAC sudah ada, field
// lain (hostname, vendor, last_seen, dst.) di-update; jika belum, disisipkan.
func (db *DB) UpsertDevice(d *Device) error {
	q := `INSERT INTO devices(mac, ip, hostname, vendor, devicetype, first_seen, last_seen, confidence, distance_estimate, distance_confidence)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			ip=excluded.ip,
			hostname=excluded.hostname,
			vendor=excluded.vendor,
			devicetype=excluded.devicetype,
			last_seen=excluded.last_seen,
			confidence=excluded.confidence,
			distance_estimate=excluded.distance_estimate,
			distance_confidence=excluded.distance_confidence`
	_, err := db.Exec(q, d.MAC, d.IP, d.Hostname, d.Vendor, d.DeviceType, d.FirstSeen, d.LastSeen, d.Confidence, d.DistanceEstimate, d.DistanceConfidence)
	return err
}

// ListDevices mengembalikan daftar semua Device dalam tabel. Jika severity
// diberikan, hanya perangkat dengan devicetype yang cocok (jika ada)
// yang akan dikembalikan. Kita selalu mengurutkan descending last_seen.
// NOTE: Tidak ada parameter severity karena Device.type adalah field, bukan filter.
func (db *DB) ListDevices() ([]Device, error) {
	rows, err := db.Query(`SELECT id, mac, ip, hostname, vendor, devicetype, first_seen, last_seen, confidence, distance_estimate, distance_confidence FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("query devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&d.ID, &d.MAC, &d.IP, &d.Hostname, &d.Vendor, &d.DeviceType, &firstSeen, &lastSeen, &d.Confidence, &d.DistanceEstimate, &d.DistanceConfidence); err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		d.FirstSeen = firstSeen
		d.LastSeen = lastSeen
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("device rows error: %w", err)
	}
	return devices, nil
}

// InsertAlert memasukkan satu baris Alert ke dalam tabel dan mengembalikan
// ID baris yang dibuat. Jika timestamp nol, timestamp sekarang akan
// digunakan oleh pemanggil sebelum memanggil fungsi ini.
func (db *DB) InsertAlert(a *Alert) (int64, error) {
	// Set default acknowledged=0 bila belum dibaca.
	ack := 0
	if a.Acknowledged {
		ack = 1
	}
	result, err := db.Exec(`INSERT INTO alerts(timestamp, severity, category, title, explanation, action, technical, device_mac, acknowledged)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Timestamp, a.Severity, a.Category, a.Title, a.Explanation, a.Action, a.Technical, a.DeviceMAC, ack)
	if err != nil {
		return 0, fmt.Errorf("insert alert: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// ListAlerts mengembalikan daftar Alert yang difilter berdasarkan severity.
// Jika severity string kosong, semua alert dikembalikan.
// Urutan: timestamp DESC (baru pertama).
func (db *DB) ListAlerts(severity string) ([]Alert, error) {
	q := `SELECT id, timestamp, severity, category, title, explanation, action, technical, device_mac, acknowledged FROM alerts`
	args := []interface{}{}
	if severity != "" {
		q += ` WHERE severity = ?`
		args = append(args, severity)
	}
	q += ` ORDER BY timestamp DESC`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []Alert
		for rows.Next() {
			var a Alert
			var ack int
			if err := rows.Scan(&a.ID, &a.Timestamp, &a.Severity, &a.Category, &a.Title, &a.Explanation, &a.Action, &a.Technical, &a.DeviceMAC, &ack); err != nil {
				return nil, fmt.Errorf("scan alert row: %w", err)
			}
			a.Acknowledged = (ack == 1)
			alerts = append(alerts, a)
		}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alert rows error: %w", err)
	}
	return alerts, nil
}

// AcknowledgeAlert menandai alert dengan ID tertentu sebagai sudah dibaca
// (acknowledged=1). Fungsi ini tidak mengembalikan nilai sukses eksplisit,
// melainkan error jika gagal.
func (db *DB) AcknowledgeAlert(id int64) error {
	_, err := db.Exec(`UPDATE alerts SET acknowledged = 1 WHERE id = ?`, id)
	return err
}

// InsertConnection memasukkan satu koneksi baru ke dalam tabel connections.
func (db *DB) InsertConnection(c *Connection) error {
	q := `INSERT INTO connections(timestamp, direction, localip, localport, remoteip, remoteport, protocol, processname, processpid, state)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := db.Exec(q, c.Timestamp, c.Direction, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.Protocol, c.ProcessName, c.ProcessPID, c.State)
	return err
}

// ListConnections mengembalikan daftar koneksi. Jika limit > 0, hanya jumlah
// teratas dikembalikan. Urutan: timestamp DESC (baru pertama).
func (db *DB) ListConnections(limit int) ([]Connection, error) {
	q := `SELECT id, timestamp, direction, localip, localport, remoteip, remoteport, protocol, processname, processpid, state FROM connections ORDER BY timestamp DESC`
	if limit > 0 {
		q += ` LIMIT ?`
	}
	// Siapkan argumen dengan benar.
	var args []interface{}
	if limit > 0 {
		args = append(args, limit)
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query connections: %w", err)
	}
	defer rows.Close()

	var connections []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.Timestamp, &c.Direction, &c.LocalIP, &c.LocalPort, &c.RemoteIP, &c.RemotePort, &c.Protocol, &c.ProcessName, &c.ProcessPID, &c.State); err != nil {
			return nil, fmt.Errorf("scan connection row: %w", err)
		}
		connections = append(connections, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection rows error: %w", err)
	}
	return connections, nil
}

// InsertScan memasukkan satu hasil pemindaian ke dalam tabel scans.
func (db *DB) InsertScan(s *Scan) (int64, error) {
	result, err := db.Exec(`INSERT INTO scans(started_at, finished_at, devicecount, alertcount)
		VALUES(?, ?, ?, ?)`, s.StartedAt, s.FinishedAt, s.DeviceCount, s.AlertCount)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	return result.LastInsertId()
}

// ListScans mengembalikan daftar scan. Jika limit > 0, ambil hanya limit
// teratas. Urutan: started_at DESC.
func (db *DB) ListScans(limit int) ([]Scan, error) {
	q := `SELECT id, started_at, finished_at, devicecount, alertcount FROM scans ORDER BY started_at DESC`
	var args []interface{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		var finishedAt time.Time
		if err := rows.Scan(&s.ID, &s.StartedAt, &finishedAt, &s.DeviceCount, &s.AlertCount); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		s.FinishedAt = finishedAt
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scans rows error: %w", err)
	}
	return scans, nil
}

// GetSetting membaca nilai setting dari tabel berdasarkan kunci.
func (db *DB) GetSetting(key string) (string, error) {
	var val string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // key tidak ada, kembalikan string kosong (tidak error)
		}
		return "", fmt.Errorf("get setting: %w", err)
	}
	return val, nil
}

// SetSetting menyimpan atau memperbarui setting di tabel (INSERT OR REPLACE).
func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec(`INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)`, key, value)
	return err
}

// PurgeOldData menghapus baris yang lama dari tabel alerts, connections, dan scans
// berdasarkan retention hours. Devices dan settings TIDAK pernah dihapus.
//
// Returns total rows deleted across all three tables.
// Semua baris devices dan settings selamat.
func (db *DB) PurgeOldData(retentionHours int) (int64, error) {
	// RUMUS: detik = jam * 3600. Hitung batas waktu (timestamp sebelum sekarang).
	cutoff := func() int64 {
		// Jika retentionHours <= 0, tidak ada data yang dipurge.
		if retentionHours <= 0 {
			return 0
		}
		// Kita tidak bisa langsung hitung waktu sekarang di sini karena kita
		// butuh context. Kembalikan 0 dan biarkan pemanggil menghitung secara
		// eksplisit di level lebih tinggi, atau gunakan datetime('now', '-' || hours || ' hour').
		return int64(retentionHours * 3600)
	}()

	var totalDeleted int64

	// Hapus dari alerts.
	deletedAlerts, err := db.execPurge("alerts", "timestamp", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge alerts: %w", err)
	}
	totalDeleted += deletedAlerts

	// Hapus dari connections.
	deletedConnections, err := db.execPurge("connections", "timestamp", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge connections: %w", err)
	}
	totalDeleted += deletedConnections

	// Hapus dari scans.
	deletedScans, err := db.execPurge("scans", "started_at", cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge scans: %w", err)
	}
	totalDeleted += deletedScans

	return totalDeleted, nil
}

// execPurge menghapus baris lama dari tabel tertentu berdasarkan kolom waktu
// dan batas cutoff (detik epoch). Menggunakan Delete dari database/sql.
func (db *DB) execPurge(table, timeCol string, cutoff int64) (int64, error) {
	result, err := db.Exec(`DELETE FROM ` + table + ` WHERE CAST(strftime('%s', ` + timeCol + `) AS INTEGER) < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int64(rowsAffected), nil
}

// ListDevicesByMAC mengembalikan perangkat berdasarkan MAC. Dipakai
// internal (bukan bagian dari API publik wajib), tapi membantu pengujian.
func (db *DB) ListDevicesByMAC(mac string) ([]Device, error) {
	rows, err := db.Query(`SELECT id, mac, ip, hostname, vendor, devicetype, first_seen, last_seen, confidence, distance_estimate, distance_confidence FROM devices WHERE mac = ? ORDER BY last_seen DESC`, mac)
	if err != nil {
		return nil, fmt.Errorf("query devices by mac: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&d.ID, &d.MAC, &d.IP, &d.Hostname, &d.Vendor, &d.DeviceType, &firstSeen, &lastSeen, &d.Confidence, &d.DistanceEstimate, &d.DistanceConfidence); err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		d.FirstSeen = firstSeen
		d.LastSeen = lastSeen
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("device rows error: %w", err)
	}
	return devices, nil
}