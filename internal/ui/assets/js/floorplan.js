// floorplan.js — Denah Lokasi Interaktif (Interactive 2D Floor Plan Canvas).
// Memungkinkan pengguna menata posisi perkiraan perangkat di dalam ruangan
// rumah/kantor dengan drag-and-drop, serta menyimpan koordinat ke localStorage.
const FloorPlan = {
    canvas: null,
    ctx: null,
    devices: [],
    selfInfo: null,
    draggingItem: null,
    hoveredItem: null,
    dragOffsetX: 0,
    dragOffsetY: 0,
    savedCoords: {},

    // Preset tata letak ruangan standar
    rooms: [
        { name: 'Ruang Kerja / Kantor', x: 40, y: 40, w: 320, h: 220, color: 'rgba(56, 189, 248, 0.08)' },
        { name: 'Ruang Tamu / Keluarga', x: 380, y: 40, w: 360, h: 220, color: 'rgba(16, 185, 129, 0.08)' },
        { name: 'Kamar Tidur Utama', x: 40, y: 280, w: 320, h: 240, color: 'rgba(168, 85, 247, 0.08)' },
        { name: 'Dapur & Ruang Makan', x: 380, y: 280, w: 360, h: 240, color: 'rgba(245, 158, 11, 0.08)' }
    ],

    init(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');

        this.loadCoords();
        this.attachEvents();

        window.addEventListener('resize', () => {
            if (this.canvas && this.canvas.offsetParent !== null) {
                this.resizeCanvas();
            }
        });
        this.resizeCanvas();
    },

    loadCoords() {
        try {
            const raw = localStorage.getItem('shadowscanner_floorplan_coords');
            if (raw) {
                this.savedCoords = JSON.parse(raw);
            }
        } catch (_) {
            this.savedCoords = {};
        }
    },

    saveCoords() {
        try {
            localStorage.setItem('shadowscanner_floorplan_coords', JSON.stringify(this.savedCoords));
        } catch (_) {}
    },

    resetCoords() {
        this.savedCoords = {};
        localStorage.removeItem('shadowscanner_floorplan_coords');
        this.autoLayoutDevices();
        this.render();
    },

    resizeCanvas() {
        const container = this.canvas.parentElement;
        if (!container) return;

        const w = container.clientWidth || 780;
        const h = Math.max(container.clientHeight || 560, 560);

        this.canvas.width = w;
        this.canvas.height = h;

        // Sesuaikan dimensi ruangan proporsional
        const margin = 20;
        const colW = (w - margin * 3) / 2;
        const rowH = (h - margin * 3) / 2;

        this.rooms[0] = { name: 'Ruang Kerja / Kantor', x: margin, y: margin, w: colW, h: rowH, color: 'rgba(56, 189, 248, 0.08)' };
        this.rooms[1] = { name: 'Ruang Tamu / Keluarga', x: margin * 2 + colW, y: margin, w: colW, h: rowH, color: 'rgba(16, 185, 129, 0.08)' };
        this.rooms[2] = { name: 'Kamar Tidur Utama', x: margin, y: margin * 2 + rowH, w: colW, h: rowH, color: 'rgba(168, 85, 247, 0.08)' };
        this.rooms[3] = { name: 'Dapur & Ruang Makan', x: margin * 2 + colW, y: margin * 2 + rowH, w: colW, h: rowH, color: 'rgba(245, 158, 11, 0.08)' };

        this.render();
    },

    setData(devices, selfInfo) {
        this.devices = devices || [];
        this.selfInfo = selfInfo || null;
        this.autoLayoutDevices();
        this.render();
    },

    autoLayoutDevices() {
        // Susun posisi awal jika belum disimpan di localStorage
        let startX = 60;
        let startY = 80;

        this.devices.forEach((dev, idx) => {
            if (!this.savedCoords[dev.mac]) {
                const roomIdx = idx % this.rooms.length;
                const room = this.rooms[roomIdx];
                const padding = 50;

                const rx = room.x + padding + ((idx * 55) % (room.w - padding * 2));
                const ry = room.y + padding + ((Math.floor(idx / 3) * 55) % (room.h - padding * 2));

                this.savedCoords[dev.mac] = { x: rx, y: ry };
            }
        });
    },

    render() {
        if (!this.ctx || !this.canvas) return;
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;

        // Bersihkan canvas
        ctx.fillStyle = '#0f172a';
        ctx.fillRect(0, 0, w, h);

        // Gambar grid tipis
        ctx.strokeStyle = '#1e293b';
        ctx.lineWidth = 1;
        const gridSize = 25;
        for (let x = 0; x < w; x += gridSize) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }
        for (let y = 0; y < h; y += gridSize) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }

        // Gambar Ruangan
        this.rooms.forEach(r => {
            ctx.fillStyle = r.color;
            ctx.fillRect(r.x, r.y, r.w, r.h);

            ctx.strokeStyle = '#334155';
            ctx.lineWidth = 1.5;
            ctx.strokeRect(r.x, r.y, r.w, r.h);

            // Label Ruangan
            ctx.fillStyle = '#94a3b8';
            ctx.font = '12px system-ui, sans-serif';
            ctx.fillText(r.name, r.x + 12, r.y + 24);
        });

        // Gambar Host Anda (Laptop/Komputer)
        const hostCoords = this.savedCoords['__self__'] || { x: this.rooms[0].x + 70, y: this.rooms[0].y + 70 };
        this.drawHostNode(ctx, hostCoords.x, hostCoords.y);

        // Gambar Perangkat Lain
        this.devices.forEach(dev => {
            const coords = this.savedCoords[dev.mac];
            if (!coords) return;

            const isHovered = (this.hoveredItem && this.hoveredItem.mac === dev.mac);
            const isDragging = (this.draggingItem && this.draggingItem.mac === dev.mac);

            this.drawDeviceNode(ctx, dev, coords.x, coords.y, isHovered || isDragging);
        });
    },

    drawHostNode(ctx, x, y) {
        // Halo pulsa
        ctx.beginPath();
        ctx.arc(x, y, 32, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(56, 189, 248, 0.12)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(x, y, 20, 0, Math.PI * 2);
        ctx.fillStyle = '#0284c7';
        ctx.strokeStyle = '#38bdf8';
        ctx.lineWidth = 2;
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = '#ffffff';
        ctx.font = '16px system-ui';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('💻', x, y);

        ctx.font = 'bold 11px system-ui';
        ctx.fillStyle = '#38bdf8';
        ctx.fillText('Host Anda', x, y + 30);
    },

    drawDeviceNode(ctx, dev, x, y, active) {
        const type = dev.device_type || 'Perangkat tidak dikenal';
        const icon = (window.NetworkGraph && window.NetworkGraph.getDeviceIcon) ?
            window.NetworkGraph.getDeviceIcon(type) : '📟';

        const isDanger = (dev.alert_count && dev.alert_count > 0);
        const radius = active ? 20 : 16;

        // Efek seleksi
        if (active) {
            ctx.beginPath();
            ctx.arc(x, y, radius + 6, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(255, 255, 255, 0.15)';
            ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fillStyle = isDanger ? '#e11d48' : '#1e293b';
        ctx.strokeStyle = isDanger ? '#fb7185' : (active ? '#38bdf8' : '#64748b');
        ctx.lineWidth = active ? 2.5 : 1.5;
        ctx.fill();
        ctx.stroke();

        // Ikon
        ctx.fillStyle = '#ffffff';
        ctx.font = active ? '15px system-ui' : '13px system-ui';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(icon, x, y);

        // Label teks
        const name = (dev.hostname || dev.vendor || dev.ip || '').substring(0, 12);
        ctx.font = '10px system-ui';
        ctx.fillStyle = active ? '#ffffff' : '#cbd5e1';
        ctx.fillText(name, x, y + radius + 11);

        ctx.font = '9px monospace';
        ctx.fillStyle = '#64748b';
        ctx.fillText(dev.ip, x, y + radius + 21);
    },

    attachEvents() {
        if (!this.canvas) return;

        const getPos = (e) => {
            const rect = this.canvas.getBoundingClientRect();
            return {
                x: e.clientX - rect.left,
                y: e.clientY - rect.top
            };
        };

        const findTarget = (pos) => {
            // Cek host
            const hostCoords = this.savedCoords['__self__'] || { x: this.rooms[0].x + 70, y: this.rooms[0].y + 70 };
            const distHost = Math.hypot(pos.x - hostCoords.x, pos.y - hostCoords.y);
            if (distHost <= 24) {
                return { isHost: true, mac: '__self__', x: hostCoords.x, y: hostCoords.y };
            }

            // Cek devices dari urutan terakhir ke awal
            for (let i = this.devices.length - 1; i >= 0; i--) {
                const dev = this.devices[i];
                const c = this.savedCoords[dev.mac];
                if (!c) continue;
                const d = Math.hypot(pos.x - c.x, pos.y - c.y);
                if (d <= 20) {
                    return { dev, mac: dev.mac, x: c.x, y: c.y };
                }
            }
            return null;
        };

        this.canvas.addEventListener('mousedown', (e) => {
            const pos = getPos(e);
            const target = findTarget(pos);
            if (target) {
                this.draggingItem = target;
                this.dragOffsetX = pos.x - target.x;
                this.dragOffsetY = pos.y - target.y;
                this.canvas.style.cursor = 'grabbing';
            }
        });

        this.canvas.addEventListener('mousemove', (e) => {
            const pos = getPos(e);

            if (this.draggingItem) {
                const newX = Math.max(20, Math.min(this.canvas.width - 20, pos.x - this.dragOffsetX));
                const newY = Math.max(20, Math.min(this.canvas.height - 20, pos.y - this.dragOffsetY));

                this.savedCoords[this.draggingItem.mac] = { x: newX, y: newY };
                this.render();
            } else {
                const target = findTarget(pos);
                this.hoveredItem = target ? target.dev : null;
                this.canvas.style.cursor = target ? 'grab' : 'default';
                this.render();
            }
        });

        const stopDrag = () => {
            if (this.draggingItem) {
                this.draggingItem = null;
                this.canvas.style.cursor = 'default';
                this.saveCoords();
                this.render();
            }
        };

        this.canvas.addEventListener('mouseup', stopDrag);
        this.canvas.addEventListener('mouseleave', stopDrag);
    }
};

window.FloorPlan = FloorPlan;
