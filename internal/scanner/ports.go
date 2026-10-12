// Package scanner menyediakan fungsi pemindaian defensif untuk jaringan lokal.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// PortResult menyimpan hasil pemeriksaan satu port pada perangkat target.
type PortResult struct {
	IP     string // Alamat IP perangkat target
	Port   int    // Nomor port yang diperiksa
	Open   bool   // true jika koneksi TCP berhasil terhubung
	Banner string // Cuplikan banner layanan (maks. 256 byte, hanya untuk port tertentu)
}

// FixedPorts adalah daftar port tetap dan terbatas yang diizinkan untuk diperiksa
// guna mengenali jenis perangkat. Tidak boleh ditambahkan port di luar daftar ini.
var FixedPorts = []int{21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080, 8443}

// CheckPorts memeriksa daftar port tetap pada alamat IP target secara defensif
// menggunakan TCP connect standar dengan batas waktu tertentu.
// Seluruh operasi mematuhi pembatalan melalui context.Context.
func CheckPorts(ctx context.Context, ip string, timeout time.Duration) ([]PortResult, error) {
	if ip == "" {
		return nil, errors.New("alamat IP tidak boleh kosong")
	}
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}

	results := make([]PortResult, len(FixedPorts))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Batasi konkuren maksimal 11 goroutine (satu per port).
	sem := make(chan struct{}, len(FixedPorts))

	for i, port := range FixedPorts {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, p int) {
			defer func() {
				<-sem
				wg.Done()
			}()

			select {
			case <-ctx.Done():
				return
			default:
			}

			targetAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
			dialer := net.Dialer{Timeout: timeout}

			conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
			if err != nil {
				mu.Lock()
				results[idx] = PortResult{
					IP:     ip,
					Port:   p,
					Open:   false,
					Banner: "",
				}
				mu.Unlock()
				return
			}
			defer conn.Close()

			res := PortResult{
				IP:     ip,
				Port:   p,
				Open:   true,
				Banner: "",
			}

			// Untuk port 21, 22, 23, 80: coba baca banner hingga 256 byte
			// dengan batas waktu 200 ms (hanya baca pasif, tanpa mengirim data).
			if p == 21 || p == 22 || p == 23 || p == 80 {
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				buf := make([]byte, 256)
				n, readErr := conn.Read(buf)
				if readErr == nil && n > 0 {
					res.Banner = string(buf[:n])
				}
			}

			mu.Lock()
			results[idx] = res
			mu.Unlock()
		}(i, port)
	}

	wg.Wait()
	return results, nil
}
