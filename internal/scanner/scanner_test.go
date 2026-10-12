package scanner

import (
	"context"
	"testing"
	"time"

	"shadowscanner/internal/config"
)

func TestScannerDiscoveryNew(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	disco, err := NewDiscovery(cfg)
	if err != nil {
		t.Fatalf("NewDiscovery failed: %v", err)
	}

	self, err := disco.Self()
	if err != nil {
		t.Logf("Self device warning (might be offline/isolated): %v", err)
	} else {
		t.Logf("Self device: MAC=%s, IP=%s, Hostname=%s, Vendor=%s",
			self.MAC, self.IP, self.Hostname, self.Vendor)
	}
}

func TestFingerprintGuess(t *testing.T) {
	dev := Device{
		MAC:      "00:26:BB:11:22:33",
		IP:       "192.168.1.100",
		Hostname: "iphone-andi",
		Vendor:   "Apple",
	}

	ports := []PortResult{
		{IP: dev.IP, Port: 80, Open: false},
		{IP: dev.IP, Port: 443, Open: false},
	}

	fp := Guess(dev, ports)
	if fp.DeviceType != "Ponsel" {
		t.Errorf("expected Ponsel, got %s", fp.DeviceType)
	}
	if fp.Confidence < 0.4 {
		t.Errorf("expected confidence >= 0.4, got %f", fp.Confidence)
	}
	t.Logf("Fingerprint: %+v", fp)
}

func TestCheckPorts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Check 127.0.0.1 with very short timeout
	results, err := CheckPorts(ctx, "127.0.0.1", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("CheckPorts failed: %v", err)
	}
	if len(results) != len(FixedPorts) {
		t.Fatalf("expected %d results, got %d", len(FixedPorts), len(results))
	}
}

func TestDistanceEstimate(t *testing.T) {
	ctx := context.Background()
	dev := Device{
		MAC: "00:11:22:33:44:55",
		IP:  "192.168.1.1",
	}

	est := Estimate(ctx, dev)
	if est.Confidence == "" || est.Method == "" {
		t.Errorf("expected non-empty Confidence and Method, got %+v", est)
	}
	t.Logf("Distance estimate: %+v", est)
}

func TestGuessISPDisabled(t *testing.T) {
	ctx := context.Background()
	info, err := GuessISP(ctx, true)
	if err != nil {
		t.Fatalf("GuessISP disabled failed: %v", err)
	}
	if !info.Disabled {
		t.Errorf("expected info.Disabled to be true")
	}
}
