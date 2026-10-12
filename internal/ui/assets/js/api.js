// api.js — Klien API terpusat untuk komunikasi REST dan Server-Sent Events (SSE).
const API = {
    async request(path, options = {}) {
        const defaultHeaders = {
            'Accept': 'application/json'
        };
        if (options.body && typeof options.body === 'object') {
            defaultHeaders['Content-Type'] = 'application/json';
            options.body = JSON.stringify(options.body);
        }

        try {
            const res = await fetch(path, {
                ...options,
                headers: {
                    ...defaultHeaders,
                    ...(options.headers || {})
                }
            });

            if (!res.ok) {
                let errorMsg = `HTTP Error ${res.status}`;
                try {
                    const errData = await res.json();
                    if (errData.error) errorMsg = errData.error;
                } catch (_) {}
                throw new Error(errorMsg);
            }

            const contentType = res.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                return await res.json();
            }
            return await res.text();
        } catch (err) {
            console.error(`[API Error] ${path}:`, err);
            throw err;
        }
    },

    get(path) {
        return this.request(path, { method: 'GET' });
    },

    post(path, body = null) {
        return this.request(path, { method: 'POST', body });
    },

    // Endpoints
    getHealth() {
        return this.get('/api/health');
    },

    getSelf() {
        return this.get('/api/self');
    },

    getDevices() {
        return this.get('/api/devices');
    },

    getAlerts() {
        return this.get('/api/alerts');
    },

    acknowledgeAlert(id) {
        return this.post(`/api/alerts/acknowledge?id=${id}`);
    },

    getConnections() {
        return this.get('/api/connections');
    },

    getHistory() {
        return this.get('/api/history');
    },

    getRecommendations() {
        return this.get('/api/recommendations');
    },

    getSettings() {
        return this.get('/api/settings');
    },

    saveSettings(settings) {
        return this.post('/api/settings', settings);
    },

    setRetention(hours) {
        return this.post(`/api/retention?hours=${hours}`);
    },

    startScan() {
        return this.post('/api/scan/start');
    },

    stopScan() {
        return this.post('/api/scan/stop');
    },

    // SSE Stream Subscriptions
    subscribeSSE(path, callbacks = {}) {
        const es = new EventSource(path);

        es.onopen = () => {
            if (callbacks.onOpen) callbacks.onOpen();
        };

        es.onerror = (err) => {
            if (callbacks.onError) callbacks.onError(err);
        };

        // Custom named events
        if (callbacks.onAlert) {
            es.addEventListener('alert', (e) => {
                try {
                    const data = JSON.parse(e.data);
                    callbacks.onAlert(data);
                } catch (err) {
                    console.error('Failed to parse SSE alert payload:', err);
                }
            });
        }

        if (callbacks.onConnection) {
            es.addEventListener('connection', (e) => {
                try {
                    const data = JSON.parse(e.data);
                    callbacks.onConnection(data);
                } catch (err) {
                    console.error('Failed to parse SSE connection payload:', err);
                }
            });
        }

        if (callbacks.onDevice) {
            es.addEventListener('device', (e) => {
                try {
                    const data = JSON.parse(e.data);
                    callbacks.onDevice(data);
                } catch (err) {
                    console.error('Failed to parse SSE device payload:', err);
                }
            });
        }

        if (callbacks.onScan) {
            es.addEventListener('scan', (e) => {
                try {
                    const data = JSON.parse(e.data);
                    callbacks.onScan(data);
                } catch (err) {
                    console.error('Failed to parse SSE scan payload:', err);
                }
            });
        }

        return es;
    }
};

window.API = API;
