// Package ui menyediakan antarmuka web statis ShadowScanner yang tertanam
// langsung ke dalam binary Go menggunakan direktif //go:embed. Pendekatan ini
// menjamin bahwa seluruh aset HTML, CSS, dan JavaScript tersedia tanpa file
// eksternal tambahan — ideal untuk distribusi desktop portabel yang aman.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assetsFS embed.FS

// Handler mengembalikan http.Handler yang melayani seluruh aset statis UI
// dari sub-direktori "assets". Aset disajikan dari root URL "/".
func Handler() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic("gagal mengakses sub-direktori assets: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}

// IndexHTML mengembalikan konten halaman utama index.html sebagai []byte.
// Berguna untuk disajikan secara manual jika rute "/" ingin ditangani khusus.
func IndexHTML() ([]byte, error) {
	return assetsFS.ReadFile("assets/index.html")
}
