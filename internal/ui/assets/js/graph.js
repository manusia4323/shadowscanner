// graph.js — Visualisasi Topologi Radial Jaringan berbasis SVG murni (tanpa library luar).
const NetworkGraph = {
    container: null,
    svg: null,
    devices: [],
    selfInfo: null,
    width: 800,
    height: 600,

    init(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) return;

        window.addEventListener('resize', () => {
            if (this.container && this.container.offsetParent !== null) {
                this.render();
            }
        });
    },

    setData(devices, selfInfo) {
        this.devices = devices || [];
        this.selfInfo = selfInfo || null;
        this.render();
    },

    render() {
        if (!this.container) return;

        const rect = this.container.getBoundingClientRect();
        this.width = Math.max(rect.width || 600, 360);
        this.height = Math.max(rect.height || 550, 480);

        const centerX = this.width / 2;
        const centerY = this.height / 2;
        const maxRadius = Math.min(centerX, centerY) - 45;

        // Radius cincin konsentris
        const ring1 = maxRadius * 0.35; // Dekat (< 3m)
        const ring2 = maxRadius * 0.65; // Sedang (3 - 8m)
        const ring3 = maxRadius * 0.95; // Jauh (> 8m / perkiraan)

        let svgHTML = `
            <svg class="radial-svg" viewBox="0 0 ${this.width} ${this.height}" width="100%" height="100%">
                <defs>
                    <!-- Efek Gradien & Bayangan -->
                    <radialGradient id="radarPulse" cx="50%" cy="50%" r="50%">
                        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.3"/>
                        <stop offset="80%" stop-color="#38bdf8" stop-opacity="0.05"/>
                        <stop offset="100%" stop-color="#38bdf8" stop-opacity="0"/>
                    </radialGradient>
                    <filter id="glow">
                        <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                        <feMerge>
                            <feMergeNode in="coloredBlur"/>
                            <feMergeNode in="SourceGraphic"/>
                        </feMerge>
                    </filter>
                </defs>

                <!-- Latar Belakang & Cincin Jarak -->
                <circle cx="${centerX}" cy="${centerY}" r="${ring3}" class="graph-ring ring-far" />
                <circle cx="${centerX}" cy="${centerY}" r="${ring2}" class="graph-ring ring-mid" />
                <circle cx="${centerX}" cy="${centerY}" r="${ring1}" class="graph-ring ring-near" />
                <circle cx="${centerX}" cy="${centerY}" r="${ring1 * 0.7}" class="graph-pulse" fill="url(#radarPulse)" />

                <!-- Label Cincin -->
                <text x="${centerX + 6}" y="${centerY - ring1 + 14}" class="graph-ring-label">Jarak Dekat (&lt;3m)</text>
                <text x="${centerX + 6}" y="${centerY - ring2 + 14}" class="graph-ring-label">Jarak Sedang (3-8m)</text>
                <text x="${centerX + 6}" y="${centerY - ring3 + 14}" class="graph-ring-label">Jarak Jauh (&gt;8m)</text>
        `;

        // Pisahkan perangkat berdasarkan jarak
        const nearDevs = [];
        const midDevs = [];
        const farDevs = [];

        this.devices.forEach(dev => {
            const dist = dev.distance_estimate || 0;
            if (dist > 0 && dist < 3.5) {
                nearDevs.push(dev);
            } else if (dist >= 3.5 && dist <= 8) {
                midDevs.push(dev);
            } else {
                farDevs.push(dev);
            }
        });

        // Hitung koordinat polar perangkat
        const placedNodes = [];

        const placeRing = (devs, radius, startAngle = 0) => {
            const count = devs.length;
            if (count === 0) return;
            const step = (Math.PI * 2) / count;

            devs.forEach((dev, idx) => {
                const angle = startAngle + idx * step;
                const x = centerX + Math.cos(angle) * radius;
                const y = centerY + Math.sin(angle) * radius;
                placedNodes.push({ dev, x, y, angle });
            });
        };

        placeRing(nearDevs, ring1, 0.2);
        placeRing(midDevs, ring2, 0.5);
        placeRing(farDevs, ring3, 0.8);

        // Garis penghubung dari Pusat ke Perangkat
        placedNodes.forEach(node => {
            svgHTML += `
                <line x1="${centerX}" y1="${centerY}" x2="${node.x}" y2="${node.y}" class="graph-link" />
            `;
        });

        // Gambar Node Pusat (Host Anda)
        const hostName = (this.selfInfo && this.selfInfo.Hostname) || 'Komputer Anda';
        const hostIP = (this.selfInfo && this.selfInfo.PrimaryIP) || '127.0.0.1';

        svgHTML += `
            <g class="graph-node host-node" transform="translate(${centerX}, ${centerY})">
                <circle cx="0" cy="0" r="24" class="node-circle-host" filter="url(#glow)" />
                <text x="0" y="5" text-anchor="middle" class="node-icon-host">💻</text>
                <text x="0" y="38" text-anchor="middle" class="node-label-host">${escapeHTML(hostName)}</text>
                <text x="0" y="50" text-anchor="middle" class="node-sublabel-host">${escapeHTML(hostIP)}</text>
            </g>
        `;

        // Gambar Node Perangkat
        placedNodes.forEach(node => {
            const d = node.dev;
            const type = d.device_type || 'Perangkat tidak dikenal';
            const icon = this.getDeviceIcon(type);
            const name = d.hostname || d.vendor || d.ip;
            const isDanger = (d.alert_count && d.alert_count > 0);

            svgHTML += `
                <g class="graph-node device-node ${isDanger ? 'node-danger' : ''}"
                   transform="translate(${node.x}, ${node.y})"
                   onclick="NetworkGraph.showDeviceDetails('${d.mac}')"
                   style="cursor: pointer;">
                    <circle cx="0" cy="0" r="18" class="node-circle-dev ${isDanger ? 'pulse-danger' : ''}" />
                    <text x="0" y="5" text-anchor="middle" class="node-icon-dev">${icon}</text>
                    <text x="0" y="28" text-anchor="middle" class="node-label-dev">${escapeHTML(name.substring(0, 14))}</text>
                    <text x="0" y="40" text-anchor="middle" class="node-sublabel-dev">${escapeHTML(d.ip)}</text>
                </g>
            `;
        });

        svgHTML += `</svg>`;
        this.container.innerHTML = svgHTML;
    },

    getDeviceIcon(type) {
        switch (type) {
            case 'Router': return '🌐';
            case 'Ponsel': return '📱';
            case 'Laptop': return '💻';
            case 'PC': return '🖥️';
            case 'Printer': return '🖨️';
            case 'TV': return '📺';
            case 'Kamera IP': return '📷';
            case 'IoT': return '💡';
            default: return '📟';
        }
    },

    showDeviceDetails(mac) {
        if (!mac || !window.App) return;
        window.App.inspectDevice(mac);
    }
};

window.NetworkGraph = NetworkGraph;
