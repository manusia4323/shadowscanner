package history

import (
	"context"
	"path/filepath"
	"testing"

	"shadowscanner/internal/config"
	"shadowscanner/internal/storage"
)

func TestRetention(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	cfg := &config.Config{
		RetentionHours: 8,
		DBPath:         dbPath,
	}

	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	r := New(cfg, db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.Start(ctx)
	// calling Start again shouldn't duplicate
	r.Start(ctx)

	if err := r.SetHours(ctx, 24); err != nil {
		t.Fatalf("SetHours failed: %v", err)
	}
	if cfg.RetentionHours != 24 {
		t.Errorf("expected 24, got %d", cfg.RetentionHours)
	}

	// invalid hours
	if err := r.SetHours(ctx, 0); err == nil {
		t.Errorf("expected error for 0 hours")
	}

	r.Stop()
	// second stop is no-op
	r.Stop()
}
