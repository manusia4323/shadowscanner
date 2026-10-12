// app.js — Pengontrol Utama Antarmuka Pengguna ShadowScanner (SPA Controller).
const App = {
    state: {
        self: null,
        devices: [],
        alerts: [],
        connections: [],
        history: [],
        recommendations: [],
        settings: {
            port: 8787,
            retention_hours: 8,
            warning_mode: true
        },
        activeTab: 'overview',
        scanning: false,
        deviceFilter: 'all',
        deviceSearch: '',
        connSearch: '',
        isOnline: true
    },

    sseAlerts: null,
    sseConns: null,
    pollTimer: null,

    async init() {
        console.log('[ShadowScanner] Memulai inisialisasi aplikasi UI...');

        // 1. Cek & Tampilkan Modal Persetujuan Pengguna (Consent Modal) jika baru pertama kali
        this.checkConsent();

        // 2. Inisialisasi modul terkait
        if (window.AlertsManager) window.AlertsManager.init();
        if (window.NetworkGraph) window.NetworkGraph.init('radial-graph-container');
        if (window.FloorPlan) window.FloorPlan.init('floorplan-canvas');

        // 3. Routing berbasis Hash URL
        this.setupRouting();

        // 4. Hubungkan Event Listener DOM
        this.attachEventListeners();

        // 5. Muat Data Awal
        await this.loadInitialData();

        // 6. Hubungkan ke Server-Sent Events (SSE)
        this.setupSSE();

        // 7. Polling berkala untuk status server & fallback data
        this.startPolling();
    },

    checkConsent() {
        const consent = localStorage.getItem('shadowscanner_consent_given');
        const modal = document.getElementById('consent-modal');
        if (!consent && modal) {
            modal.style.display = 'flex';
        }
    },

    acceptConsent() {
        localStorage.setItem('shadowscanner_consent_given', 'true');
        const modal = document.getElementById('consent-modal');
        if (modal) modal.style.display = 'none';
    },

    setupRouting() {
        const handleHash = () => {
            let hash = window.location.hash.replace('#', '') || 'overview';
            const validTabs = ['overview', 'devices', 'graph', 'floorplan', 'alerts', 'connections', 'history'];
            if (!validTabs.includes(hash)) {
                hash = 'overview';
            }
            this.switchTab(hash);
        };

        window.addEventListener('hashchange', handleHash);
        handleHash();
    },

    switchTab(tabName) {
        this.state.activeTab = tabName;

        // Update nav pills / buttons
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.toggle('active', el.getAttribute('data-tab') === tabName);
        });

        // Update tab view panels
        document.querySelectorAll('.tab-view').forEach(el => {
            el.classList.toggle('active', el.id === `view-${tabName}`);
        });

        // Trigger rerender jika masuk ke visualisasi
        if (tabName === 'graph' && window.NetworkGraph) {
            setTimeout(() => window.NetworkGraph.render(), 50);
        } else if (tabName === 'floorplan' && window.FloorPlan) {
            setTimeout(() => window.FloorPlan.resizeCanvas(), 50);
        }
    },

    attachEventListeners() {
        // Tombol Persetujuan
        const btnConsent = document.getElementById('btn-accept-consent');
        if (btnConsent) {
            btnConsent.addEventListener('click', () => this.acceptConsent());
        }

        // Tombol Navigasi
        document.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', (e) => {
                e.preventDefault();
                const tab = el.getAttribute('data-tab');
                window.location.hash = `#${tab}`;
            });
        });

        // Tombol Pindai (Scan)
        const btnScan = document.getElementById('btn-toggle-scan');
        if (btnScan) {
            btnScan.addEventListener('click', () => this.toggleScan());
        }

        // Filter & Search Perangkat
        const devSearch = document.getElementById('input-search-devices');
        if (devSearch) {
            devSearch.addEventListener('input', (e) => {
                this.state.deviceSearch = e.target.value.toLowerCase();
                this.renderDevicesList();
            });
        }

        document.querySelectorAll('.btn-filter-type').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.btn-filter-type').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.state.deviceFilter = btn.getAttribute('data-type');
                this.renderDevicesList();
            });
        });

        // Search Koneksi Aktif
        const connSearch = document.getElementById('input-search-conns');
        if (connSearch) {
            connSearch.addEventListener('input', (e) => {
                this.state.connSearch = e.target.value.toLowerCase();
                this.renderConnections();
            });
        }

        // Pengaturan Retensi Jam
        const retentionSlider = document.getElementById('range-retention-hours');
        const retentionVal = document.getElementById('label-retention-hours');
        if (retentionSlider && retentionVal) {
            retentionSlider.addEventListener('input', (e) => {
                retentionVal.textContent = `${e.target.value} jam`;
            });
            retentionSlider.addEventListener('change', async (e) => {
                const hours = parseInt(e.target.value, 10);
                try {
                    await API.setRetention(hours);
                    this.state.settings.retention_hours = hours;
                } catch (err) {
                    alert('Gagal menyimpan retensi: ' + err.message);
                }
            });
        }

        // Pengaturan Warning Mode Switch
        const warnToggle = document.getElementById('toggle-warning-mode');
        if (warnToggle) {
            warnToggle.addEventListener('change', async (e) => {
                const isWarn = e.target.checked;
                try {
                    await API.saveSettings({ warning_mode: isWarn ? 'true' : 'false' });
                    this.state.settings.warning_mode = isWarn;
                } catch (err) {
                    alert('Gagal menyimpan mode peringatan: ' + err.message);
                }
            });
        }

        // Tombol Reset Denah
        const btnResetFloorplan = document.getElementById('btn-reset-floorplan');
        if (btnResetFloorplan && window.FloorPlan) {
            btnResetFloorplan.addEventListener('click', () => window.FloorPlan.resetCoords());
        }

        // Modal Tutup Device Detail
        const btnCloseModal = document.getElementById('btn-close-device-modal');
        const modalOverlay = document.getElementById('device-modal');
        if (btnCloseModal && modalOverlay) {
            btnCloseModal.addEventListener('click', () => modalOverlay.style.display = 'none');
            modalOverlay.addEventListener('click', (e) => {
                if (e.target === modalOverlay) modalOverlay.style.display = 'none';
            });
        }
    },

    async loadInitialData() {
        try {
            const [health, self, devices, alerts, conns, history, recs, settings] = await Promise.all([
                API.getHealth().catch(() => null),
                API.getSelf().catch(() => null),
                API.getDevices().catch(() => []),
                API.getAlerts().catch(() => []),
                API.getConnections().catch(() => []),
                API.getHistory().catch(() => []),
                API.getRecommendations().catch(() => []),
                API.getSettings().catch(() => ({}))
            ]);

            this.state.self = self;
            this.state.devices = devices || [];
            this.state.alerts = alerts || [];
            this.state.connections = conns || [];
            this.state.history = history || [];
            this.state.recommendations = recs || [];
            if (settings) this.state.settings = { ...this.state.settings, ...settings };

            this.updateHealthIndicator(health !== null);
            this.renderAll();
        } catch (err) {
            console.error('Gagal memuat data awal:', err);
        }
    },

    setupSSE() {
        // Aliran Peringatan (Alerts Stream)
        this.sseAlerts = API.subscribeSSE('/api/alerts/stream', {
            onAlert: (newAlert) => {
                if (window.AlertsManager) {
                    window.AlertsManager.addAlert(newAlert);
                }
                this.refreshCounts();
            },
            onDevice: (newDev) => {
                this.upsertLocalDevice(newDev);
            },
            onScan: (scanEvent) => {
                if (scanEvent.status === 'started') {
                    this.setScanningState(true);
                } else if (scanEvent.status === 'completed' || scanEvent.status === 'stopped' || scanEvent.status === 'error') {
                    this.setScanningState(false);
                    this.refreshDevices();
                    this.refreshHistory();
                }
            }
        });

        // Aliran Koneksi Aktif (Connections Stream)
        this.sseConns = API.subscribeSSE('/api/connections/stream', {
            onConnection: (newConn) => {
                this.state.connections.unshift(newConn);
                if (this.state.connections.length > 200) {
                    this.state.connections.pop();
                }
                if (this.state.activeTab === 'connections') {
                    this.renderConnections();
                }
                this.refreshCounts();
            }
        });
    },

    startPolling() {
        this.pollTimer = setInterval(async () => {
            try {
                const health = await API.getHealth();
                this.updateHealthIndicator(true);
            } catch (_) {
                this.updateHealthIndicator(false);
            }
        }, 6000);
    },

    updateHealthIndicator(online) {
        this.state.isOnline = online;
        const pill = document.getElementById('server-status-pill');
        if (pill) {
            pill.className = `status-pill ${online ? 'online' : 'offline'}`;
            pill.innerHTML = online ? '● Server Aktif' : '○ Terputus';
        }
    },

    async toggleScan() {
        const btn = document.getElementById('btn-toggle-scan');
        if (this.state.scanning) {
            // Hentikan
            try {
                await API.stopScan();
                this.setScanningState(false);
            } catch (err) {
                alert('Gagal menghentikan pemindaian: ' + err.message);
            }
        } else {
            // Mulai
            try {
                this.setScanningState(true);
                await API.startScan();
            } catch (err) {
                this.setScanningState(false);
                alert('Gagal memulai pemindaian: ' + err.message);
            }
        }
    },

    setScanningState(isScanning) {
        this.state.scanning = isScanning;
        const btn = document.getElementById('btn-toggle-scan');
        const badge = document.getElementById('scan-status-badge');

        if (btn) {
            btn.innerHTML = isScanning ?
                '<span class="spinner"></span> Berhenti' :
                '🔍 Pindai Jaringan';
            btn.classList.toggle('btn-danger', isScanning);
            btn.classList.toggle('btn-primary', !isScanning);
        }

        if (badge) {
            badge.style.display = isScanning ? 'inline-block' : 'none';
        }
    },

    async refreshDevices() {
        try {
            const devs = await API.getDevices();
            this.state.devices = devs || [];
            this.renderOverview();
            this.renderDevicesList();
            if (window.NetworkGraph) window.NetworkGraph.setData(this.state.devices, this.state.self);
            if (window.FloorPlan) window.FloorPlan.setData(this.state.devices, this.state.self);
            this.refreshCounts();
        } catch (_) {}
    },

    async refreshHistory() {
        try {
            const h = await API.getHistory();
            this.state.history = h || [];
            this.renderHistory();
        } catch (_) {}
    },

    upsertLocalDevice(dev) {
        const idx = this.state.devices.findIndex(d => d.mac === dev.mac);
        if (idx >= 0) {
            this.state.devices[idx] = dev;
        } else {
            this.state.devices.push(dev);
        }
        this.renderDevicesList();
        if (window.NetworkGraph) window.NetworkGraph.setData(this.state.devices, this.state.self);
        if (window.FloorPlan) window.FloorPlan.setData(this.state.devices, this.state.self);
        this.refreshCounts();
    },

    refreshCounts() {
        const countDev = document.getElementById('stat-total-devices');
        if (countDev) countDev.textContent = this.state.devices.length;

        const countAlert = document.getElementById('stat-active-alerts');
        const unreadAlerts = this.state.alerts.filter(a => !a.acknowledged).length;
        if (countAlert) countAlert.textContent = unreadAlerts;

        const countConn = document.getElementById('stat-active-conns');
        if (countConn) countConn.textContent = this.state.connections.length;
    },

    renderAll() {
        this.renderOverview();
        this.renderDevicesList();
        if (window.AlertsManager) {
            window.AlertsManager.setAlerts(this.state.alerts);
            window.AlertsManager.setRecommendations(this.state.recommendations);
        }
        if (window.NetworkGraph) {
            window.NetworkGraph.setData(this.state.devices, this.state.self);
        }
        if (window.FloorPlan) {
            window.FloorPlan.setData(this.state.devices, this.state.self);
        }
        this.renderConnections();
        this.renderHistory();
        this.renderSettings();
        this.refreshCounts();
    },

    renderOverview() {
        const self = this.state.self;
        if (!self) return;

        // Host card
        const elHostName = document.getElementById('self-hostname');
        if (elHostName) elHostName.textContent = self.Hostname || '-';

        const elHostIP = document.getElementById('self-ip');
        if (elHostIP) elHostIP.textContent = self.PrimaryIP || '-';

        const elHostMAC = document.getElementById('self-mac');
        if (elHostMAC) elHostMAC.textContent = self.PrimaryMAC || '-';

        const elGateway = document.getElementById('self-gateway');
        if (elGateway) elGateway.textContent = self.GatewayIP || '-';

        const elOS = document.getElementById('self-os');
        if (elOS) elOS.textContent = `${self.OS || '-'} (${self.Arch || '-'})`;

        // ISP Card
        const elISPName = document.getElementById('isp-name');
        if (elISPName) elISPName.textContent = self.ISPInfo && self.ISPInfo.ISPName ? self.ISPInfo.ISPName : 'Privasi Aman / Lokal';

        const elPublicIP = document.getElementById('isp-public-ip');
        if (elPublicIP) elPublicIP.textContent = self.ISPInfo && self.ISPInfo.PublicIP ? self.ISPInfo.PublicIP : '-';
    },

    renderDevicesList() {
        const container = document.getElementById('devices-grid-container');
        if (!container) return;

        let filtered = this.state.devices.filter(d => {
            // Type filter
            if (this.state.deviceFilter !== 'all' && d.device_type !== this.state.deviceFilter) {
                return false;
            }
            // Search filter
            if (this.state.deviceSearch) {
                const q = this.state.deviceSearch;
                const matchIP = (d.ip || '').toLowerCase().includes(q);
                const matchMAC = (d.mac || '').toLowerCase().includes(q);
                const matchName = (d.hostname || '').toLowerCase().includes(q);
                const matchVendor = (d.vendor || '').toLowerCase().includes(q);
                return matchIP || matchMAC || matchName || matchVendor;
            }
            return true;
        });

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="empty-state-card col-span-full">
                    <p>Tidak ada perangkat yang cocok dengan kriteria pencarian.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = filtered.map(d => {
            const typeLabel = I18N.translateDeviceType(d.device_type);
            const icon = window.NetworkGraph ? window.NetworkGraph.getDeviceIcon(d.device_type) : '📟';
            const distText = I18N.formatDistance(d.distance_estimate, d.distance_confidence);
            const isAlert = d.alert_count && d.alert_count > 0;

            return `
                <div class="device-card ${isAlert ? 'border-danger' : ''}" onclick="App.inspectDevice('${d.mac}')">
                    <div class="device-card-header">
                        <div class="device-icon-wrapper">${icon}</div>
                        <div class="device-header-info">
                            <h4 class="device-name">${escapeHTML(d.hostname || d.vendor || 'Perangkat Tanpa Nama')}</h4>
                            <span class="device-type-badge">${escapeHTML(typeLabel)}</span>
                        </div>
                    </div>
                    <div class="device-card-body">
                        <div class="detail-row">
                            <span class="label">IP:</span>
                            <span class="val font-mono">${escapeHTML(d.ip)}</span>
                        </div>
                        <div class="detail-row">
                            <span class="label">MAC:</span>
                            <span class="val font-mono">${escapeHTML(d.mac)}</span>
                        </div>
                        <div class="detail-row">
                            <span class="label">Pabrikan:</span>
                            <span class="val">${escapeHTML(d.vendor || 'Tidak diketahui')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="label">Jarak Perkiraan:</span>
                            <span class="val">${escapeHTML(distText)}</span>
                        </div>
                    </div>
                    <div class="device-card-footer">
                        <span class="last-seen">Dilihat ${I18N.formatTimeAgo(d.last_seen)}</span>
                        <button class="btn btn-xs btn-outline">Detail &raquo;</button>
                    </div>
                </div>
            `;
        }).join('');
    },

    inspectDevice(mac) {
        const d = this.state.devices.find(item => item.mac === mac);
        if (!d) return;

        const modal = document.getElementById('device-modal');
        const modalBody = document.getElementById('device-modal-body');
        if (!modal || !modalBody) return;

        const icon = window.NetworkGraph ? window.NetworkGraph.getDeviceIcon(d.device_type) : '📟';
        const typeLabel = I18N.translateDeviceType(d.device_type);
        const distText = I18N.formatDistance(d.distance_estimate, d.distance_confidence);

        modalBody.innerHTML = `
            <div class="modal-device-header">
                <div class="device-avatar">${icon}</div>
                <div>
                    <h3>${escapeHTML(d.hostname || d.vendor || 'Perangkat Jaringan')}</h3>
                    <div class="device-type-badge">${escapeHTML(typeLabel)}</div>
                </div>
            </div>
            <div class="device-modal-specs">
                <div class="spec-item"><span class="label">Alamat IP</span><strong class="font-mono">${escapeHTML(d.ip)}</strong></div>
                <div class="spec-item"><span class="label">Alamat Fisik (MAC)</span><strong class="font-mono">${escapeHTML(d.mac)}</strong></div>
                <div class="spec-item"><span class="label">Pabrikan (OUI)</span><strong>${escapeHTML(d.vendor || 'Tidak terdeteksi')}</strong></div>
                <div class="spec-item"><span class="label">Tingkat Keyakinan</span><strong>${Math.round((d.confidence || 0) * 100)}%</strong></div>
                <div class="spec-item"><span class="label">Estimasi Jarak</span><strong>${escapeHTML(distText)}</strong></div>
                <div class="spec-item"><span class="label">Pertama Kali Dilihat</span><strong>${I18N.formatDateTime(d.first_seen)}</strong></div>
                <div class="spec-item"><span class="label">Terakhir Terdeteksi</span><strong>${I18N.formatDateTime(d.last_seen)}</strong></div>
            </div>
        `;

        modal.style.display = 'flex';
    },

    renderConnections() {
        const tbody = document.getElementById('conns-table-body');
        if (!tbody) return;

        let filtered = this.state.connections;
        if (this.state.connSearch) {
            const q = this.state.connSearch;
            filtered = filtered.filter(c =>
                (c.process_name || '').toLowerCase().includes(q) ||
                (c.remote_ip || '').toLowerCase().includes(q) ||
                (c.local_ip || '').toLowerCase().includes(q)
            );
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4">Tidak ada koneksi aktif yang sesuai</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.slice(0, 100).map(c => `
            <tr>
                <td><strong>${escapeHTML(c.process_name || 'System')}</strong> <small class="text-muted">(PID ${c.pid || '-'})</small></td>
                <td><span class="badge-proto">${escapeHTML(c.protocol || 'TCP')}</span></td>
                <td class="font-mono">${escapeHTML(c.local_ip)}:${c.local_port}</td>
                <td class="font-mono">${escapeHTML(c.remote_ip)}:${c.remote_port}</td>
                <td><span class="badge-status">${escapeHTML(c.state || 'ESTABLISHED')}</span></td>
                <td>${I18N.formatTimeAgo(c.first_seen)}</td>
            </tr>
        `).join('');
    },

    renderHistory() {
        const tbody = document.getElementById('history-table-body');
        if (!tbody) return;

        if (this.state.history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4">Belum ada riwayat pemindaian</td></tr>`;
            return;
        }

        tbody.innerHTML = this.state.history.map(h => `
            <tr>
                <td>${I18N.formatDateTime(h.started_at)}</td>
                <td>${I18N.formatDateTime(h.finished_at)}</td>
                <td><strong>${h.device_count}</strong> perangkat</td>
                <td><span class="${h.alert_count > 0 ? 'text-danger font-bold' : 'text-muted'}">${h.alert_count} peringatan</span></td>
                <td><span class="badge-info">Selesai</span></td>
            </tr>
        `).join('');
    },

    renderSettings() {
        const slider = document.getElementById('range-retention-hours');
        const label = document.getElementById('label-retention-hours');
        const warn = document.getElementById('toggle-warning-mode');

        if (slider && this.state.settings.retention_hours) {
            slider.value = this.state.settings.retention_hours;
        }
        if (label && this.state.settings.retention_hours) {
            label.textContent = `${this.state.settings.retention_hours} jam`;
        }
        if (warn && typeof this.state.settings.warning_mode !== 'undefined') {
            warn.checked = !!this.state.settings.warning_mode;
        }
    }
};

window.App = App;

// Jalankan ketika DOM sudah siap
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
