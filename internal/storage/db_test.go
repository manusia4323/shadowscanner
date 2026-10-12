package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorageDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	// 1. Test UpsertDevice
	now := time.Now().Truncate(time.Second)
	dev := &Device{
		MAC:                 "00:11:22:33:44:55",
		IP:                  "192.168.1.50",
		Hostname:            "my-laptop",
		Vendor:              "Dell",
		DeviceType:          "Laptop",
		FirstSeen:           now,
		LastSeen:            now,
		Confidence:          0.8,
		DistanceEstimate:    3.5,
		DistanceConfidence:  "sedang",
	}

	if err := db.UpsertDevice(dev); err != nil {
		t.Fatalf("UpsertDevice insert failed: %v", err)
	}

	// Update device with new IP and last seen
	dev.IP = "192.168.1.51"
	dev.LastSeen = now.Add(time.Minute)
	if err := db.UpsertDevice(dev); err != nil {
		t.Fatalf("UpsertDevice update failed: %v", err)
	}

	devices, err := db.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].IP != "192.168.1.51" {
		t.Fatalf("expected updated IP 192.168.1.51, got %s", devices[0].IP)
	}

	// 2. Test Alert
	alert := &Alert{
		Timestamp:   now,
		Severity:    "bahaya",
		Category:    "arp",
		Title:       "Router palsu terdeteksi",
		Explanation: "Ada perangkat menyamar sebagai gateway",
		Action:      "Putuskan WiFi segera",
		Technical:   "IP 192.168.1.1 dipetakan ke 2 MAC",
		DeviceMAC:   "00:11:22:33:44:55",
	}
	id, err := db.InsertAlert(alert)
	if err != nil {
		t.Fatalf("InsertAlert failed: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected alert id > 0, got %d", id)
	}

	alerts, err := db.ListAlerts("")
	if err != nil {
		t.Fatalf("ListAlerts failed: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Acknowledged {
		t.Fatalf("unexpected alerts result: %+v", alerts)
	}

	if err := db.AcknowledgeAlert(id); err != nil {
		t.Fatalf("AcknowledgeAlert failed: %v", err)
	}
	alerts, _ = db.ListAlerts("")
	if !alerts[0].Acknowledged {
		t.Fatalf("expected alert to be acknowledged")
	}

	// 3. Test Connection
	conn := &Connection{
		Timestamp:   now,
		Direction:   "keluar",
		LocalIP:     "192.168.1.50",
		LocalPort:   54321,
		RemoteIP:    "1.1.1.1",
		RemotePort:  443,
		Protocol:    "TCP",
		ProcessName: "curl",
		ProcessPID:  1234,
		State:       "ESTABLISHED",
	}
	if err := db.InsertConnection(conn); err != nil {
		t.Fatalf("InsertConnection failed: %v", err)
	}
	conns, err := db.ListConnections(10)
	if err != nil {
		t.Fatalf("ListConnections failed: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	// 4. Test Scan
	scan := &Scan{
		StartedAt:   now,
		FinishedAt:  now.Add(5 * time.Second),
		DeviceCount: 1,
		AlertCount:  1,
	}
	scanID, err := db.InsertScan(scan)
	if err != nil {
		t.Fatalf("InsertScan failed: %v", err)
	}
	if scanID <= 0 {
		t.Fatalf("expected scan id > 0, got %d", scanID)
	}
	scans, err := db.ListScans(10)
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}

	// 5. Test Settings
	if err := db.SetSetting("test_key", "test_val"); err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}
	val, err := db.GetSetting("test_key")
	if err != nil || val != "test_val" {
		t.Fatalf("GetSetting expected test_val, got %s, err: %v", val, err)
	}

	// 6. Test PurgeOldData (should not delete recent records)
	deleted, err := db.PurgeOldData(24)
	if err != nil {
		t.Fatalf("PurgeOldData failed: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted, got %d", deleted)
	}

	_ = os.Remove(dbPath)
}
