package local

import (
	"context"
	"testing"
)

func TestLocalGet(t *testing.T) {
	ctx := context.Background()
	info, err := Get(ctx)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	t.Logf("Hostname: %s, OS: %s, Arch: %s, PrimaryIP: %s, GatewayIP: %s",
		info.Hostname, info.OS, info.Arch, info.PrimaryIP, info.GatewayIP)
}

func TestListNetworkProcesses(t *testing.T) {
	ctx := context.Background()
	procs, err := ListNetworkProcesses(ctx)
	if err != nil {
		t.Fatalf("ListNetworkProcesses() error: %v", err)
	}
	t.Logf("Found %d network processes", len(procs))
}
