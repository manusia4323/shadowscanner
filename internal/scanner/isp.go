// Package scanner menyediakan fungsi pemindaian defensif untuk jaringan lokal.
// CATATAN PRIVASI: File ini adalah SATU-SATUNYA bagian dari seluruh aplikasi ShadowScanner
// yang melakukan permintaan keluar (outbound request). Hanya ditujukan untuk memeriksa
// alamat IP publik dan ISP pengguna. Tidak ada data lokal (IP lokal, MAC, nama host,
// atau daftar perangkat) yang pernah dikirim ke luar. Fitur ini dapat dinonaktifkan
// kapan saja dengan menyetel argumen disabled = true.
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ISPInfo menyimpan informasi alamat IP publik dan penyedia internet (ISP) pengguna.
type ISPInfo struct {
	PublicIP string // Alamat IP publik pengguna
	ISPName  string // Nama ISP / Organisasi (misal: "Telkom Indonesia", "Indosat")
	ASN      string // Autonomous System Number (misal: "AS7713")
	Country  string // Kode negara (misal: "ID")
	Disabled bool   // true jika fitur permintaan IP publik dinonaktifkan
}

// GuessISP memeriksa IP publik dan ISP pengguna melalui endpoint privasi eksternal.
// Jika disabled bernilai true, fungsi langsung mengembalikan ISPInfo{Disabled: true}
// tanpa melakukan panggilan jaringan sama sekali.
func GuessISP(ctx context.Context, disabled bool) (ISPInfo, error) {
	if disabled {
		return ISPInfo{Disabled: true}, nil
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Coba endpoint utama (ipinfo.io)
	info, err := fetchIPInfo(ctx, client)
	if err == nil {
		return info, nil
	}

	// Fallback ke endpoint alternatif (ifconfig.co) jika endpoint utama gagal
	info, fallbackErr := fetchIfconfigCo(ctx, client)
	if fallbackErr == nil {
		return info, nil
	}

	return ISPInfo{}, fmt.Errorf("gagal mendapatkan informasi ISP: %w (fallback: %v)", err, fallbackErr)
}

// fetchIPInfo mengambil data dari https://ipinfo.io/json
func fetchIPInfo(ctx context.Context, client *http.Client) (ISPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json", nil)
	if err != nil {
		return ISPInfo{}, err
	}
	req.Header.Set("User-Agent", "ShadowScanner-Defensive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ISPInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ISPInfo{}, fmt.Errorf("status HTTP tidak terduga: %d", resp.StatusCode)
	}

	var payload struct {
		IP      string `json:"ip"`
		Org     string `json:"org"`
		Country string `json:"country"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ISPInfo{}, err
	}

	ispName, asn := parseOrgField(payload.Org)

	return ISPInfo{
		PublicIP: payload.IP,
		ISPName:  ispName,
		ASN:      asn,
		Country:  payload.Country,
		Disabled: false,
	}, nil
}

// fetchIfconfigCo mengambil data dari https://ifconfig.co/json
func fetchIfconfigCo(ctx context.Context, client *http.Client) (ISPInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ifconfig.co/json", nil)
	if err != nil {
		return ISPInfo{}, err
	}
	req.Header.Set("User-Agent", "ShadowScanner-Defensive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ISPInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ISPInfo{}, fmt.Errorf("status HTTP tidak terduga: %d", resp.StatusCode)
	}

	var payload struct {
		IP         string `json:"ip"`
		ASNOrg     string `json:"asn_org"`
		ASN        string `json:"asn"`
		CountryISO string `json:"country_iso"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ISPInfo{}, err
	}

	if payload.IP == "" {
		return ISPInfo{}, errors.New("respons kosong dari ifconfig.co")
	}

	return ISPInfo{
		PublicIP: payload.IP,
		ISPName:  payload.ASNOrg,
		ASN:      payload.ASN,
		Country:  payload.CountryISO,
		Disabled: false,
	}, nil
}

// parseOrgField memisahkan field "org" ipinfo.io (format: "AS7713 PT Telekomunikasi Indonesia")
// menjadi nama ISP dan nomor ASN.
func parseOrgField(org string) (string, string) {
	org = strings.TrimSpace(org)
	if org == "" {
		return "Tidak diketahui", ""
	}

	parts := strings.SplitN(org, " ", 2)
	if len(parts) == 2 && strings.HasPrefix(parts[0], "AS") {
		return parts[1], parts[0]
	}
	return org, ""
}
