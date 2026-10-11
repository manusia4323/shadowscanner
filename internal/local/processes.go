// Package processes menyediakan daftar proses yang saat ini membuka
// koneksi jaringan, dalam bahasa Indonesia yang mudah dipahami.
package local

import (
	"context"
	"sort"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/shirou/gopsutil/v4/net"
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
// Fungsi ini read-only: tidak pernah membunuh, menyuspend, atau memodifikasi
// proses apa pun, dan tidak pernah membaca memori proses.
func ListNetworkProcesses(ctx context.Context) ([]ProcNetInfo, error) {
	// Dapatkan semua koneksi TCP
	tcpConns, err := net.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, fmt.Errorf("get TCP connections: %w", err)
	}

	// Kelompokkan koneksi berdasarkan PID
	type pidInfo struct {
		pids        []int
		remoteIPs   map[string]struct{}
	}
	byPID := make(map[int]*pidInfo)
	for _, c := range tcpConns {
		if c.Pid == 0 {
			continue
		}
		info, ok := byPID[int(c.Pid)]
		if !ok {
			info = &pidInfo{remoteIPs: make(map[string]struct{})}
			byPID[int(c.Pid)] = info
		}
		info.pids = append(info.pids, int(c.Pid))
		if c.Raddr.IP != "" && c.Raddr.IP != "0.0.0.0" && c.Raddr.IP != "::1" && c.Raddr.IP != "127.0.0.1" {
			info.remoteIPs[c.Raddr.IP] = struct{}{}
		}
	}

	// Gabungkan PID duplikat dan ambil info proses
	var result []ProcNetInfo
	for pid, info := range byPID {
		// Ambil info proses untuk PID pertama (semua PID duplikat adalah proses yang sama)
		p, err := process.NewProcess(int64(pid))
		if err != nil {
			// Ijin rendah: catat di log dan lanjutkan, jangan gagal
			slog.Warn("tidak dapat mengambil info proses (mungkin butuh izin)", "pid", pid, "error", err)
			continue
		}

		// Gabungkan semua executable path dari PID duplikat
		var exePaths []string
		seen := make(map[string]struct{})
		for _, pids := range info.pids {
			pp, err := process.NewProcess(int64(pids))
			if err != nil {
				continue
			}
			if pe, err := pp.Exe(); err == nil && pe != "" {
				if _, ok := seen[pe]; !ok {
					seen[pe] = struct{}{}
					exePaths = append(exePaths, pe)
				}
			}
		}
		exe := ""
		if len(exePaths) > 0 {
			exe = exePaths[0]
		}

		name := "Tidak diketahui"
		if n, err := p.Name(); err == nil && n != "" {
			name = n
		}

		hostList := make([]string, 0, len(info.remoteIPs))
		for ip := range info.remoteIPs {
			hostList = append(hostList, ip)
		}

		result = append(result, ProcNetInfo{
			PID:         pid,
			Name:        name,
			Exe:         exe,
			Connections: len(info.pids),
			RemoteHosts: hostList,
		})
	}

	// Urutkan dari koneksi terbanyak ke sedikit
	sort.Slice(result, func(i, j int) bool {
		return result[i].Connections > result[j].Connections
	})

	return result, nil
}