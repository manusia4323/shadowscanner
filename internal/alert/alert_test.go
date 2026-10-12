package alert

import (
	"path/filepath"
	"testing"
	"time"

	"shadowscanner/internal/storage"
)

func TestAlertConstructorsAndEngine(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	engine := NewEngine(db)

	// Test alert creation
	arpAlert := ARPSpoofing("192.168.1.1", "00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
	if arpAlert.Severity != SeverityDanger {
		t.Errorf("expected SeverityDanger, got %s", arpAlert.Severity)
	}

	if err := engine.Raise(arpAlert); err != nil {
		t.Fatalf("engine.Raise failed: %v", err)
	}

	alerts, err := db.ListAlerts("")
	if err != nil || len(alerts) != 1 {
		t.Fatalf("expected 1 alert in db, got %d (err: %v)", len(alerts), err)
	}

	if err := engine.Acknowledge(alerts[0].ID); err != nil {
		t.Fatalf("engine.Acknowledge failed: %v", err)
	}
}

func TestAdvisoryGenerate(t *testing.T) {
	alerts := []Alert{
		{
			ID:          1,
			Timestamp:   time.Now(),
			Severity:    SeverityDanger,
			Category:    "arp",
			Title:       "Ada perangkat berpura-pura jadi router",
			Explanation: "ARP spoofing",
			Action:      "Putuskan koneksi",
		},
	}
	devices := []storage.Device{
		{
			ID:  1,
			MAC: "00:11:22:33:44:55",
			IP:  "192.168.1.5",
		},
	}

	recs := Generate(alerts, devices)
	if len(recs) == 0 {
		t.Fatalf("expected recommendations when danger alert exists")
	}

	foundARP := false
	for _, r := range recs {
		if r.Severity == SeverityDanger {
			foundARP = true
			break
		}
	}
	if !foundARP {
		t.Errorf("expected danger recommendation in %+v", recs)
	}
}
