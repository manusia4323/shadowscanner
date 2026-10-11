// Package isp guesses the user's ISP from the public IP address.
// Only makes ONE outbound HTTPS request (to ipinfo.io or ifconfig.co)
// and only if not disabled. No local IP, MAC, hostname, or device list
// is ever sent externally.
package isp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ISPInfo holds public IP and ISP information.
type ISPInfo struct {
	PublicIP string // Public IP address
	ISPName  string // ISP name (e.g., "Telkom Indonesia", "Indihome")
	ASN      string // Autonomous System Number
	Country  string // Country code
	Disabled bool   // True if public IP lookup is disabled
}

// GuessISP fetches the public IP and ISP info from a privacy-friendly endpoint.
// If disabled is true, returns ISPInfo{Disabled: true} immediately without
// making any network request.
// Uses https://ipinfo.io/json or https://ifconfig.co/json with 3s timeout.
// On any error, returns empty ISPInfo with the error wrapped.
func GuessISP(ctx context.Context, disabled bool) (ISPInfo, error) {
	if disabled {
		return ISPInfo{Disabled: true}, nil
	}

	// Create HTTP client with 3 second timeout
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Try primary endpoint (ipinfo.io)
	info, err := fetchFromIPInfo(ctx, client)
	if err == nil {
		return info, nil
	}

	// Try fallback endpoint (ifconfig.co)
	info, err = fetchFromIfConfig(ctx, client)
	if err == nil {
		return info, nil
	}

	// Both failed
	return ISPInfo{}, fmt.Errorf("failed to fetch ISP info: %w", err)
}

// fetchFromIPInfo queries https://ipinfo.io/json
func fetchFromIPInfo(ctx context.Context, client *http.Client) (ISPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	if err != nil {
		return ISPInfo{}, fmt.Errorf("create request: %w", err)
	}
	// Add User-Agent for identification
	req.Header.Set("User-Agent", "ShadowScanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ISPInfo{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ISPInfo{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var data struct {
		IP    string `json:"ip"`
		Org   string `json:"org"`   // e.g., "AS3320 Deutsche Telekom AG"
		City  string `json:"city"`
		Region string `json:"region"`
		Country string `json:"country"`
		ASN    string `json:"asn"`   // Some responses may include ASN separately
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ISPInfo{}, fmt.Errorf("decode response: %w", err)
	}

	// Extract ISP name from org field (typically "AS<number> <ISP name>")
	ispName := extractISPName(data.Org)
	asn := extractASN(data.Org)

	return ISPInfo{
		PublicIP: data.IP,
		ISPName:  ispName,
		ASN:      asn,
		Country:  data.Country,
		Disabled: false,
	}, nil
}

// fetchFromIfConfig queries https://ifconfig.co/json
func fetchFromIfConfig(ctx context.Context, client *http.Client) (ISPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ifconfig.co/json", nil)
	if err != nil {
		return ISPInfo{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "ShadowScanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ISPInfo{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ISPInfo{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var data struct {
		IP    string `json:"ip"`
		ISP   string `json:"isp"`   // ISP name
		ASN   string `json:"asn"`   // ASN if available
		Country string `json:"country_iso"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ISPInfo{}, fmt.Errorf("decode response: %w", err)
	}

	return ISPInfo{
		PublicIP: data.IP,
		ISPName:  data.ISP,
		ASN:      data.ASN,
		Country:  data.Country,
		Disabled: false,
	}, nil
}

// extractISPName extracts the ISP name from ipinfo.io's "org" field.
// Example: "AS3320 Deutsche Telekom AG" -> "Deutsche Telekom AG"
func extractISPName(org string) string {
	// Format is typically "AS<number> <Name>"
	parts := strings.SplitN(org, " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return org
}

// extractASN extracts the ASN from ipinfo.io's "org" field.
// Example: "AS3320 Deutsche Telekom AG" -> "3320"
func extractASN(org string) string {
	parts := strings.SplitN(org, " ", 2)
	if len(parts) >= 1 && strings.HasPrefix(parts[0], "AS") {
		return strings.TrimPrefix(parts[0], "AS")
	}
	return ""
}