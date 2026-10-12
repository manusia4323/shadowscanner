// alerts.js — Pengelola tampilan peringatan keamanan dan saran tindakan (advisories).
const AlertsManager = {
    alerts: [],
    recommendations: [],

    init() {
        // Event listener delegasi untuk tombol konfirmasi baca
        document.addEventListener('click', (e) => {
            if (e.target && e.target.classList.contains('btn-ack-alert')) {
                const alertId = e.target.getAttribute('data-alert-id');
                if (alertId) {
                    this.acknowledge(alertId);
                }
            }
        });
    },

    setAlerts(alertsList) {
        this.alerts = alertsList || [];
        this.render();
    },

    setRecommendations(recsList) {
        this.recommendations = recsList || [];
        this.renderRecommendations();
    },

    addAlert(alertItem) {
        // Cek jika sudah ada
        const exists = this.alerts.some(a => a.id === alertItem.id);
        if (!exists) {
            this.alerts.unshift(alertItem);
            this.render();
            this.showToast(alertItem);
        }
    },

    async acknowledge(id) {
        try {
            await API.acknowledgeAlert(id);
            // Update status lokal
            const item = this.alerts.find(a => a.id == id);
            if (item) {
                item.acknowledged = true;
            }
            this.render();
            if (window.App && window.App.refreshCounts) {
                window.App.refreshCounts();
            }
        } catch (err) {
            alert('Gagal menandai peringatan sebagai dibaca: ' + err.message);
        }
    },

    render() {
        const container = document.getElementById('alerts-list-container');
        const emptyState = document.getElementById('alerts-empty-state');
        const badgeCount = document.getElementById('badge-unread-alerts');

        if (!container) return;

        const unreadCount = this.alerts.filter(a => !a.acknowledged).length;
        if (badgeCount) {
            badgeCount.textContent = unreadCount;
            badgeCount.style.display = unreadCount > 0 ? 'inline-block' : 'none';
        }

        if (this.alerts.length === 0) {
            container.innerHTML = '';
            if (emptyState) emptyState.style.display = 'block';
            return;
        }

        if (emptyState) emptyState.style.display = 'none';

        container.innerHTML = this.alerts.map(a => {
            const sev = I18N.severities[a.severity] || I18N.severities['info'];
            const isAck = !!a.acknowledged;
            const timeAgo = I18N.formatTimeAgo(a.timestamp);
            const fullTime = I18N.formatDateTime(a.timestamp);

            return `
                <div class="alert-card ${a.severity} ${isAck ? 'acknowledged' : ''}">
                    <div class="alert-card-header">
                        <div class="alert-title-row">
                            <span class="severity-badge ${sev.badgeClass}">
                                ${sev.icon} ${sev.label}
                            </span>
                            <span class="alert-category-tag">${I18N.translateAlertCategory(a.category)}</span>
                            <h4 class="alert-title">${escapeHTML(a.title)}</h4>
                        </div>
                        <div class="alert-time" title="${fullTime}">${timeAgo}</div>
                    </div>

                    <div class="alert-body">
                        <div class="alert-section">
                            <strong>Penjelasan Sederhana:</strong>
                            <p>${escapeHTML(a.explanation)}</p>
                        </div>

                        ${a.action ? `
                        <div class="alert-section action-box">
                            <strong>Langkah yang Perlu Dilakukan:</strong>
                            <p>${escapeHTML(a.action)}</p>
                        </div>` : ''}

                        ${a.technical ? `
                        <details class="alert-technical-details">
                            <summary>Detail Teknis Tambahan</summary>
                            <pre><code>${escapeHTML(a.technical)}</code></pre>
                        </details>` : ''}
                    </div>

                    <div class="alert-footer">
                        ${a.device_mac ? `<span class="alert-device-mac">Alamat MAC: <code>${escapeHTML(a.device_mac)}</code></span>` : '<span></span>'}
                        ${!isAck ? `
                            <button class="btn btn-sm btn-outline btn-ack-alert" data-alert-id="${a.id}">
                                ✓ Tandai Sudah Dibaca
                            </button>
                        ` : `
                            <span class="text-muted"><small>✓ Telah ditinjau</small></span>
                        `}
                    </div>
                </div>
            `;
        }).join('');
    },

    renderRecommendations() {
        const container = document.getElementById('recommendations-list-container');
        if (!container) return;

        if (!this.recommendations || this.recommendations.length === 0) {
            container.innerHTML = `
                <div class="empty-state-mini">
                    <p>✓ Jaringan Anda tampak aman. Tidak ada tindakan darurat yang diperlukan saat ini.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = this.recommendations.map(r => {
            const sev = I18N.severities[r.severity] || I18N.severities['info'];
            return `
                <div class="recommendation-card ${r.severity}">
                    <div class="rec-icon">${sev.icon}</div>
                    <div class="rec-content">
                        <h5>${escapeHTML(r.title)}</h5>
                        <p class="rec-desc">${escapeHTML(r.description)}</p>
                        <div class="rec-steps">
                            <strong>Langkah Praktis:</strong>
                            <ol>
                                ${r.steps.map(s => `<li>${escapeHTML(s)}</li>`).join('')}
                            </ol>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    },

    showToast(alertItem) {
        const toast = document.createElement('div');
        toast.className = `app-toast toast-${alertItem.severity || 'info'}`;
        toast.innerHTML = `
            <div class="toast-title">⚠️ Peringatan Baru Terdeteksi</div>
            <div class="toast-msg">${escapeHTML(alertItem.title)}</div>
        `;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('visible');
        }, 50);

        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 400);
        }, 5000);
    }
};

function escapeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

window.AlertsManager = AlertsManager;
