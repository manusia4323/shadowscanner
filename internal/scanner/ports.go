// Package ports implements checking a small, fixed list of common ports on
// devices to help guess device type. This is not an offensive port scanner.
// It only performs TCP connect checks with timeouts and light banner reading.
package ports

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

// PortResult holds the result of checking a single port on a device.
type PortResult struct {
	IP    string
	Port  int
	Open  bool
	Banner string
}

// CheckPorts checks a small, fixed list of common ports on the given IP.
// It returns a slice of PortResult for each port in the list.
// The context is used for cancellation.
// The fixed port list is: 21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080, 8443
func CheckPorts(ctx context.Context, ip string, timeout time.Duration) ([]PortResult, error) {
	if ip == "" {
		return nil, errors.New("IP address is required")
	}
	if timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}

	// Fixed list of ports to check (do not modify)
	ports := []int{21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080, 8443}

	results := make([]PortResult, len(ports))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check all ports concurrently with a limit of 11 goroutines (one per port)
	sem := make(chan struct{}, len(ports)) // allow all to run concurrently (11 total)

	for i, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p int) {
			defer func() {
				wg.Done()
				<-sem
			}()

			// Check if context is cancelled before starting
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Attempt TCP connect with timeout
			address := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err != nil {
				// Connection failed or timeout - port is closed or unreachable
				mu.Lock()
				results[idx] = PortResult{
					IP:    ip,
					Port:  p,
					Open:  false,
					Banner: "",
				}
				mu.Unlock()
				return
			}
			defer conn.Close()

			// Connection succeeded - port is open
			result := PortResult{
				IP:    ip,
				Port:  p,
				Open:  true,
				Banner: "",
			}

			// For ports 21, 22, 23, 80: attempt to read a banner (max 256 bytes)
			// with a 200ms read deadline. This is read-only, no data sent.
			if p == 21 || p == 22 || p == 23 || p == 80 {
				// Set read deadline
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err == nil && n > 0 {
					// Successfully read banner data
					result.Banner = string(buf[:n])
				}
				// If err != nil (timeout or error), we leave Banner empty
				// This is fine - we tried but got no banner
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, port)
	}
	wg.Wait()

	return results, nil
}