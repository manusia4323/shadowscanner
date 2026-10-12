// i18n.js — Kamus Bahasa Indonesia dan utilitas pemformatan teks ramah pengguna.
const I18N = {
    // Tipe Perangkat
    deviceTypes: {
        'Router': 'Router / Gerbang Jaringan',
        'Ponsel': 'Ponsel / Smartphone',
        'Laptop': 'Laptop Portabel',
        'PC': 'Komputer Desktop (PC)',
        'Printer': 'Printer Jaringan',
        'TV': 'Smart TV / Streaming',
        'Kamera IP': 'Kamera Pengawas (IP Cam)',
        'IoT': 'Perangkat Pintar (IoT)',
        'Perangkat tidak dikenal': 'Perangkat Lain / Belum Dikenali'
    },

    // Kategori Peringatan
    alertCategories: {
        'arp': 'Pemalsuan Router (ARP Spoofing)',
        'mac': 'Duplikasi Alamat MAC (MAC Spoofing)',
        'dhcp': 'Server DHCP Liar (Rogue DHCP)',
        'gateway': 'Perubahan Gerbang Jaringan',
        'dns': 'Pengalihan DNS Mencurigakan',
        'script': 'Penyusupan Skrip Web'
    },

    // Tingkat Bahaya (Severity)
    severities: {
        'bahaya': {
            label: 'Bahaya Kritis',
            badgeClass: 'badge-danger',
            color: '#f43f5e',
            icon: '⚠️'
        },
        'peringatan': {
            label: 'Peringatan',
            badgeClass: 'badge-warning',
            color: '#f59e0b',
            icon: '⚡'
        },
        'info': {
            label: 'Informasi',
            badgeClass: 'badge-info',
            color: '#38bdf8',
            icon: 'ℹ️'
        }
    },

    // Tingkat Akurasi Jarak
    distanceConfidence: {
        'tinggi': 'Akurasi Tinggi (Sinyal Terdeteksi)',
        'sedang': 'Akurasi Sedang',
        'rendah': 'Perkiraan Kasar'
    },

    // Format jarak
    formatDistance(meters, confidence) {
        if (!meters || meters <= 0) {
            return 'Jarak tidak diketahui';
        }
        const m = meters.toFixed(1);
        const confText = this.distanceConfidence[confidence] || 'Perkiraan';
        return `± ${m} meter (${confText})`;
    },

    // Terjemahkan tipe perangkat
    translateDeviceType(type) {
        return this.deviceTypes[type] || type || 'Perangkat Belum Dikenali';
    },

    // Terjemahkan kategori peringatan
    translateAlertCategory(cat) {
        return this.alertCategories[cat] || cat || 'Keamanan Umum';
    },

    // Format waktu relatif (contoh: "baru saja", "3 menit lalu")
    formatTimeAgo(dateInput) {
        if (!dateInput) return '-';
        const date = new Date(dateInput);
        const now = new Date();
        const diffSeconds = Math.floor((now - date) / 1000);

        if (diffSeconds < 5) return 'baru saja';
        if (diffSeconds < 60) return `${diffSeconds} detik lalu`;
        const diffMinutes = Math.floor(diffSeconds / 60);
        if (diffMinutes < 60) return `${diffMinutes} menit lalu`;
        const diffHours = Math.floor(diffMinutes / 60);
        if (diffHours < 24) return `${diffHours} jam lalu`;
        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays} hari lalu`;
    },

    // Format tanggal dan jam lengkap
    formatDateTime(dateInput) {
        if (!dateInput) return '-';
        const d = new Date(dateInput);
        return d.toLocaleString('id-ID', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }
};

window.I18N = I18N;
