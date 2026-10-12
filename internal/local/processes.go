// Package local menyediakan daftar proses yang saat ini membuka
// koneksi jaringan, dalam bahasa Indonesia yang mudah dipahami.
package local

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// ProcNetInfo merekam informasi tentang satu proses yang membuka koneksi jaringan.
type ProcNetInfo struct {
	PID         int      // ID proses
	Name        string   // Nama proses
	Exe         string   // Lokasi file executable
	Connections int      // Jumlah koneksi aktif yang dibuka proses ini
	RemoteHosts []string // Daftar host jarak jauh yang dihubungi (dedup)
}

// ListNetworkProcesses mengembalikan daftar proses yang saat ini membuka
// koneksi TCP, diurutkan dari yang paling banyak koneksi ke yang paling sedikit.
//
// Fungsi ini bersifat read-only: tidak pernah membunuh, menghentikan, atau
// memodifikasi proses apa pun, dan tidak pernah membaca memori proses.
func ListNetworkProcesses(ctx context.Context) ([]ProcNetInfo, error) {
	conns, err := net.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, fmt.Errorf("gagal membaca koneksi TCP: %w", err)
	}

	// Kelompokkan koneksi berdasarkan PID
	type procData struct {
		remoteSet map[string]struct{}
		count     int
	}

	byPID := make(map[int]*procData)
	for _, c := range conns {
		pid := int(c.Pid)
		if pid <= 0 {
			continue
		}

		pd, ok := byPID[pid]
		if !ok {
			pd = &procData{remoteSet: make(map[string]struct{})}
			byPID[pid] = pd
		}
		pd.count++

		remoteIP := c.Raddr.IP
		if remoteIP != "" && remoteIP != "0.0.0.0" && remoteIP != "::" && remoteIP != "127.0.0.1" && remoteIP != "::1" {
			pd.remoteSet[remoteIP] = struct{}{}
		}
	}

	results := make([]ProcNetInfo, 0, len(byPID))
	for pid, pd := range byPID {
		name := "Tidak diketahui"
		exe := ""

		p, err := process.NewProcessWithContext(ctx, int32(pid))
		if err == nil {
			if n, err := p.NameWithContext(ctx); err == nil && n != "" {
				name = n
			}
			if e, err := p.ExeWithContext(ctx); err == nil && e != "" {
				exe = e
			}
		} else {
			slog.Debug("izin terbatas saat membaca proses", "pid", pid, "error", err)
		}

		hosts := make([]string, 0, len(pd.remoteSet))
		for h := range pd.remoteSet {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)

		results = append(results, ProcNetInfo{
			PID:         pid,
			Name:        name,
			Exe:         exe,
			Connections: pd.count,
			RemoteHosts: hosts,
		})
	}

	// Urutkan dari jumlah koneksi terbanyak ke paling sedikit
	sort.Slice(results, func(i, j int) bool {
		if results[i].Connections != results[j].Connections {
			return results[i].Connections > results[j].Connections
		}
		return results[i].PID < results[j].PID
	})

	return results, nil
}