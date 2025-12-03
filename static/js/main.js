/**
 * WARHAMMER - Network Overlay Management System
 * Main JavaScript Application
 */

// ==================== GLOBAL STATE ====================

let socket = null;
let networkChart = null;
let latencyChart = null;
let map = null;
let peerMarkers = {};
let refreshIntervals = {};
let lastMetrics = null;
let logs = [];

const MAX_CHART_POINTS = 60;
const chartData = {
    labels: [],
    rx: [],
    tx: []
};

const latencyData = {
    labels: [],
    values: []
};

// ==================== INITIALIZATION ====================

function initApp(config) {
    console.log('WARHAMMER initializing...', config);

    // Initialize WebSocket
    initSocket();

    // Initialize Charts
    initNetworkChart();
    initLatencyChart();

    // Initialize Map if token provided
    if (config.mapboxToken) {
        initMap(config.mapboxToken);
    }

    // Start data fetching
    fetchSystemInfo();
    fetchNetworkInterfaces();
    fetchServices();
    fetchNetbirdStatus();
    fetchPeers();
    fetchRoutes();

    // Set up refresh intervals
    refreshIntervals.systemInfo = setInterval(fetchSystemInfo, 5000);
    refreshIntervals.interfaces = setInterval(fetchNetworkInterfaces, 10000);
    refreshIntervals.services = setInterval(fetchServices, 30000);
    refreshIntervals.peers = setInterval(fetchPeers, 15000);
    refreshIntervals.netbird = setInterval(fetchNetbirdStatus, 30000);

    // Add initial log
    addLog('INFO', 'WARHAMMER interface initialized');
}

// ==================== WEBSOCKET ====================

function initSocket() {
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionAttempts: 10
    });

    socket.on('connect', () => {
        updateConnectionStatus('connected', 'ONLINE');
        setActivityIndicator(true);
        addLog('SUCCESS', 'WebSocket connected');
    });

    socket.on('disconnect', () => {
        updateConnectionStatus('error', 'OFFLINE');
        setActivityIndicator(false);
        addLog('ERROR', 'WebSocket disconnected');
    });

    socket.on('connect_error', (error) => {
        updateConnectionStatus('error', 'ERROR');
        console.error('Socket connection error:', error);
    });

    socket.on('metrics_update', (data) => {
        updateMetrics(data);
    });

    socket.on('error', (data) => {
        addLog('ERROR', data.message);
    });
}

function updateConnectionStatus(status, text) {
    const indicator = document.getElementById('connectionStatus');
    indicator.className = `status-indicator ${status}`;
    indicator.querySelector('.status-text').textContent = text;
}

function setActivityIndicator(active) {
    const indicator = document.getElementById('activityIndicator');
    if (active) {
        indicator.classList.add('active');
    } else {
        indicator.classList.remove('active');
    }
}

// ==================== DATA FETCHING ====================

async function fetchSystemInfo() {
    try {
        const response = await fetch('/api/system/info');
        const data = await response.json();

        if (data.error) {
            throw new Error(data.error);
        }

        // Update CPU
        updateGauge('cpu', data.cpu_percent);
        document.getElementById('cpuValue').textContent = `${data.cpu_percent.toFixed(1)}%`;

        // Update Memory
        updateGauge('mem', data.memory_percent);
        document.getElementById('memValue').textContent = `${data.memory_percent.toFixed(1)}%`;

        // Update Disk
        updateGauge('disk', data.disk_percent);

        // Update uptime
        document.getElementById('systemUptime').textContent = data.uptime;

        // Update temperature
        if (data.temperatures && Object.keys(data.temperatures).length > 0) {
            const temp = Object.values(data.temperatures)[0];
            const tempEl = document.getElementById('tempValue');
            tempEl.textContent = `${temp.toFixed(1)}°C`;
            tempEl.className = 'temp-value' + (temp > 80 ? ' danger' : temp > 60 ? ' warning' : '');
        }

    } catch (error) {
        console.error('Error fetching system info:', error);
    }
}

async function fetchNetworkInterfaces() {
    try {
        const response = await fetch('/api/network/interfaces');
        const interfaces = await response.json();

        if (interfaces.error) {
            throw new Error(interfaces.error);
        }

        const container = document.getElementById('interfaceList');
        container.innerHTML = '';

        document.getElementById('interfaceCount').textContent = interfaces.length;

        interfaces.forEach(iface => {
            const ipv4 = iface.addresses.find(a => a.type === 'ipv4');
            const div = document.createElement('div');
            div.className = `interface-item ${iface.is_up ? '' : 'down'}`;
            div.innerHTML = `
                <div class="interface-info">
                    <div class="interface-name">${iface.name}</div>
                    <div class="interface-ip">${ipv4 ? ipv4.address : 'No IP'}</div>
                </div>
                <span class="interface-status ${iface.is_up ? 'up' : 'down'}">
                    ${iface.is_up ? 'UP' : 'DOWN'}
                </span>
            `;
            container.appendChild(div);
        });

    } catch (error) {
        console.error('Error fetching interfaces:', error);
    }
}

async function fetchServices() {
    try {
        const response = await fetch('/api/sbc/services');
        const services = await response.json();

        if (services.error) {
            throw new Error(services.error);
        }

        const container = document.getElementById('serviceList');
        container.innerHTML = '';

        services.forEach(service => {
            const div = document.createElement('div');
            div.className = 'service-item';
            div.innerHTML = `
                <span class="service-name">${service.name}</span>
                <span class="service-status ${service.active ? 'active' : 'inactive'}">
                    ${service.status.toUpperCase()}
                </span>
            `;
            container.appendChild(div);
        });

    } catch (error) {
        console.error('Error fetching services:', error);
    }
}

async function fetchNetbirdStatus() {
    try {
        const response = await fetch('/api/netbird/status');
        const data = await response.json();

        const statusEl = document.getElementById('netbirdStatus');

        if (data.error) {
            statusEl.textContent = 'OFFLINE';
            statusEl.className = 'netbird-status disconnected';
            return;
        }

        statusEl.textContent = 'CONNECTED';
        statusEl.className = 'netbird-status connected';

        // Update details
        if (data.daemonVersion) {
            document.getElementById('nbVersion').textContent = data.daemonVersion;
        }
        if (data.publicKey) {
            document.getElementById('nbPubKey').textContent = data.publicKey.substring(0, 20) + '...';
        }
        if (data.fqdn) {
            document.getElementById('nbFqdn').textContent = data.fqdn;
        }

    } catch (error) {
        console.error('Error fetching Netbird status:', error);
        const statusEl = document.getElementById('netbirdStatus');
        statusEl.textContent = 'ERROR';
        statusEl.className = 'netbird-status disconnected';
    }
}

async function fetchPeers() {
    try {
        const response = await fetch('/api/netbird/peers');
        const peers = await response.json();

        if (peers.error) {
            addLog('WARN', `Peers fetch: ${peers.error}`);
            return;
        }

        const container = document.getElementById('peerList');
        container.innerHTML = '';

        document.getElementById('peerCount').textContent = peers.length;
        document.getElementById('peerCounter').textContent = peers.length;

        peers.forEach(peer => {
            const isOnline = peer.connected || peer.status === 'connected';
            const div = document.createElement('div');
            div.className = `peer-item ${isOnline ? 'online' : 'offline'}`;
            div.onclick = () => showPeerDetails(peer);

            div.innerHTML = `
                <div class="peer-status-dot"></div>
                <div class="peer-info">
                    <div class="peer-name">${peer.name || peer.hostname || 'Unknown'}</div>
                    <div class="peer-ip">${peer.ip || peer.ipAddress || '--'}</div>
                </div>
                ${peer.latency ? `<div class="peer-latency ${getLatencyClass(peer.latency)}">${peer.latency}ms</div>` : ''}
            `;

            container.appendChild(div);

            // Update map marker if map exists
            if (map && peer.geoNameId) {
                updatePeerMarker(peer);
            }
        });

        // Update latency chart with online peers
        updateLatencyChart(peers.filter(p => p.connected));

    } catch (error) {
        console.error('Error fetching peers:', error);
    }
}

async function fetchRoutes() {
    try {
        const response = await fetch('/api/netbird/routes');
        const routes = await response.json();

        if (routes.error) {
            return;
        }

        const container = document.getElementById('routeList');
        container.innerHTML = '';

        document.getElementById('routeCounter').textContent = routes.length;

        routes.forEach(route => {
            const div = document.createElement('div');
            div.className = 'route-item';
            div.innerHTML = `
                <div>
                    <div class="route-network">${route.network || route.networkRange}</div>
                    <div class="route-via">via ${route.peer || route.description || 'Direct'}</div>
                </div>
                <span class="route-status ${route.enabled ? 'enabled' : 'disabled'}">
                    ${route.enabled ? 'ENABLED' : 'DISABLED'}
                </span>
            `;
            container.appendChild(div);
        });

    } catch (error) {
        console.error('Error fetching routes:', error);
    }
}

// ==================== METRICS UPDATE ====================

function updateMetrics(data) {
    // Calculate rates if we have previous data
    if (lastMetrics) {
        const timeDelta = (data.timestamp - lastMetrics.timestamp) / 1000;
        const rxRate = (data.rx_bytes - lastMetrics.rx_bytes) / timeDelta;
        const txRate = (data.tx_bytes - lastMetrics.tx_bytes) / timeDelta;

        // Update rate displays
        document.getElementById('rxRate').textContent = formatBytes(rxRate) + '/s';
        document.getElementById('txRate').textContent = formatBytes(txRate) + '/s';

        // Update chart
        updateNetworkChart(rxRate, txRate);
    }

    // Update totals
    document.getElementById('totalRx').textContent = formatBytes(data.rx_bytes);
    document.getElementById('totalTx').textContent = formatBytes(data.tx_bytes);

    // Update header values
    if (data.cpu !== undefined) {
        const cpuEl = document.getElementById('cpuValue');
        cpuEl.textContent = `${data.cpu.toFixed(1)}%`;
        cpuEl.className = 'info-value' + (data.cpu > 80 ? ' danger' : data.cpu > 60 ? ' warning' : '');
    }

    if (data.memory !== undefined) {
        const memEl = document.getElementById('memValue');
        memEl.textContent = `${data.memory.toFixed(1)}%`;
        memEl.className = 'info-value' + (data.memory > 85 ? ' danger' : data.memory > 70 ? ' warning' : '');
    }

    lastMetrics = data;
}

// ==================== CHARTS ====================

function initNetworkChart() {
    const ctx = document.getElementById('networkChart').getContext('2d');

    networkChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Download',
                    data: [],
                    borderColor: '#30d158',
                    backgroundColor: 'rgba(48, 209, 88, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                },
                {
                    label: 'Upload',
                    data: [],
                    borderColor: '#ff6b35',
                    backgroundColor: 'rgba(255, 107, 53, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 300
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(18, 14, 12, 0.95)',
                    titleColor: '#ff6b35',
                    bodyColor: '#e8e0d8',
                    borderColor: 'rgba(255, 107, 53, 0.3)',
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            return context.dataset.label + ': ' + formatBytes(context.raw) + '/s';
                        }
                    }
                }
            },
            scales: {
                x: {
                    display: false
                },
                y: {
                    display: true,
                    grid: {
                        color: 'rgba(255, 107, 53, 0.1)'
                    },
                    ticks: {
                        color: '#584838',
                        font: {
                            family: 'Share Tech Mono',
                            size: 10
                        },
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });
}

function updateNetworkChart(rx, tx) {
    const now = new Date();
    const label = now.toLocaleTimeString();

    chartData.labels.push(label);
    chartData.rx.push(rx);
    chartData.tx.push(tx);

    // Keep only last N points
    if (chartData.labels.length > MAX_CHART_POINTS) {
        chartData.labels.shift();
        chartData.rx.shift();
        chartData.tx.shift();
    }

    networkChart.data.labels = chartData.labels;
    networkChart.data.datasets[0].data = chartData.rx;
    networkChart.data.datasets[1].data = chartData.tx;
    networkChart.update('none');
}

function initLatencyChart() {
    const ctx = document.getElementById('latencyChart').getContext('2d');

    latencyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: function(context) {
                    const value = context.raw;
                    if (value < 50) return 'rgba(48, 209, 88, 0.7)';
                    if (value < 100) return 'rgba(255, 176, 0, 0.7)';
                    return 'rgba(255, 59, 48, 0.7)';
                },
                borderColor: function(context) {
                    const value = context.raw;
                    if (value < 50) return '#30d158';
                    if (value < 100) return '#ffb000';
                    return '#ff3b30';
                },
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 300
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(18, 14, 12, 0.95)',
                    titleColor: '#ff6b35',
                    bodyColor: '#e8e0d8',
                    callbacks: {
                        label: function(context) {
                            return context.raw + ' ms';
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#584838',
                        font: {
                            family: 'Share Tech Mono',
                            size: 9
                        },
                        maxRotation: 45
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 107, 53, 0.1)'
                    },
                    ticks: {
                        color: '#584838',
                        font: {
                            family: 'Share Tech Mono',
                            size: 10
                        },
                        callback: function(value) {
                            return value + 'ms';
                        }
                    }
                }
            }
        }
    });
}

function updateLatencyChart(peers) {
    const labels = [];
    const data = [];

    peers.slice(0, 8).forEach(peer => {
        if (peer.latency) {
            labels.push(peer.name || peer.hostname || peer.ip);
            data.push(peer.latency);
        }
    });

    latencyChart.data.labels = labels;
    latencyChart.data.datasets[0].data = data;
    latencyChart.update('none');
}

// ==================== MAP ====================

function initMap(token) {
    mapboxgl.accessToken = token;

    map = new mapboxgl.Map({
        container: 'mapContainer',
        style: 'mapbox://styles/mapbox/dark-v11',
        center: [-98.5795, 39.8283], // Center of US
        zoom: 3
    });

    map.addControl(new mapboxgl.NavigationControl(), 'top-right');

    map.on('load', () => {
        addLog('INFO', 'Map initialized');
    });
}

function updatePeerMarker(peer) {
    // This would require geocoding or stored coordinates
    // Placeholder for map marker functionality
}

function centerMap() {
    if (map) {
        map.flyTo({
            center: [-98.5795, 39.8283],
            zoom: 3,
            duration: 1000
        });
    }
}

// ==================== GAUGES ====================

function updateGauge(type, percent) {
    const fill = document.getElementById(`${type}GaugeFill`);
    const value = document.getElementById(`${type}GaugeValue`);

    // Calculate stroke-dashoffset (283 is circumference of circle with r=45)
    const offset = 283 - (283 * percent / 100);
    fill.style.strokeDashoffset = offset;

    // Update color based on value
    fill.classList.remove('warning', 'danger');
    if (percent > 80) {
        fill.classList.add('danger');
    } else if (percent > 60) {
        fill.classList.add('warning');
    }

    value.textContent = `${percent.toFixed(0)}%`;
}

// ==================== UI INTERACTIONS ====================

function toggleSection(header) {
    const section = header.parentElement;
    section.classList.toggle('collapsed');
}

function filterPeers() {
    const search = document.getElementById('peerSearch').value.toLowerCase();
    const items = document.querySelectorAll('.peer-item');

    items.forEach(item => {
        const name = item.querySelector('.peer-name').textContent.toLowerCase();
        const ip = item.querySelector('.peer-ip').textContent.toLowerCase();

        if (name.includes(search) || ip.includes(search)) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
}

function refreshPeers() {
    fetchPeers();
    addLog('INFO', 'Refreshing peer list...');
}

function showPeerDetails(peer) {
    const modal = document.getElementById('peerModal');
    const content = document.getElementById('peerModalContent');

    content.innerHTML = `
        <div class="peer-details">
            <div class="info-row">
                <span class="info-label">Name:</span>
                <span class="info-value">${peer.name || peer.hostname || 'Unknown'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">IP Address:</span>
                <span class="info-value">${peer.ip || peer.ipAddress || '--'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Status:</span>
                <span class="info-value">${peer.connected ? 'Connected' : 'Disconnected'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">OS:</span>
                <span class="info-value">${peer.os || '--'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Version:</span>
                <span class="info-value">${peer.version || '--'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Last Seen:</span>
                <span class="info-value">${peer.lastSeen ? new Date(peer.lastSeen).toLocaleString() : '--'}</span>
            </div>
            ${peer.groups ? `
            <div class="info-row">
                <span class="info-label">Groups:</span>
                <span class="info-value">${peer.groups.map(g => g.name || g).join(', ')}</span>
            </div>
            ` : ''}
        </div>
        <div class="btn-group" style="margin-top: 15px;">
            <button class="btn btn-primary" onclick="pingPeer('${peer.ip || peer.ipAddress}')">PING</button>
            <button class="btn btn-secondary" onclick="closePeerModal()">CLOSE</button>
        </div>
    `;

    modal.classList.remove('hidden');
}

function closePeerModal() {
    document.getElementById('peerModal').classList.add('hidden');
}

async function pingPeer(ip) {
    if (!ip) return;

    addLog('INFO', `Pinging ${ip}...`);

    try {
        const response = await fetch(`/api/ping/${ip}`);
        const data = await response.json();

        if (data.status === 'online') {
            addLog('SUCCESS', `Ping to ${ip}: ${data.latency}ms`);
        } else {
            addLog('WARN', `Ping to ${ip}: ${data.status}`);
        }
    } catch (error) {
        addLog('ERROR', `Ping failed: ${error.message}`);
    }
}

// ==================== SETTINGS ====================

function openSettingsModal() {
    document.getElementById('settingsModal').classList.remove('hidden');
}

function closeSettingsModal() {
    document.getElementById('settingsModal').classList.add('hidden');
}

function showSettingsTab(tab) {
    // Hide all tabs
    document.querySelectorAll('.settings-content').forEach(el => {
        el.classList.remove('active');
    });
    document.querySelectorAll('.settings-tab').forEach(el => {
        el.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(`settings${tab.charAt(0).toUpperCase() + tab.slice(1)}`).classList.add('active');
    event.target.classList.add('active');
}

// ==================== CONFIRM DIALOGS ====================

function showConfirm(title, message, callback) {
    const modal = document.getElementById('confirmModal');
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMessage').textContent = message;

    const yesBtn = document.getElementById('confirmYes');
    yesBtn.onclick = () => {
        callback();
        closeConfirmModal();
    };

    modal.classList.remove('hidden');
}

function closeConfirmModal() {
    document.getElementById('confirmModal').classList.add('hidden');
}

function confirmReboot() {
    showConfirm('CONFIRM REBOOT', 'Are you sure you want to reboot the system?', async () => {
        try {
            await fetch('/api/sbc/power', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reboot' })
            });
            addLog('WARN', 'System rebooting...');
        } catch (error) {
            addLog('ERROR', 'Reboot failed: ' + error.message);
        }
    });
}

function confirmShutdown() {
    showConfirm('CONFIRM SHUTDOWN', 'Are you sure you want to shutdown the system?', async () => {
        try {
            await fetch('/api/sbc/power', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'shutdown' })
            });
            addLog('WARN', 'System shutting down...');
        } catch (error) {
            addLog('ERROR', 'Shutdown failed: ' + error.message);
        }
    });
}

// ==================== LOGGING ====================

function addLog(level, message) {
    const container = document.getElementById('logContainer');
    const now = new Date();
    const timeStr = now.toLocaleTimeString();

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${timeStr}</span>
        <span class="log-level ${level}">${level}</span>
        <span class="log-message">${message}</span>
    `;

    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;

    // Keep only last 100 logs
    logs.push({ time: timeStr, level, message });
    if (logs.length > 100) {
        logs.shift();
        container.removeChild(container.firstChild);
    }
}

function clearLog() {
    document.getElementById('logContainer').innerHTML = '';
    logs = [];
    addLog('INFO', 'Log cleared');
}

// ==================== UTILITIES ====================

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function getLatencyClass(latency) {
    if (latency < 50) return 'good';
    if (latency < 100) return 'medium';
    return 'poor';
}

// ==================== KEYBOARD SHORTCUTS ====================

document.addEventListener('keydown', (e) => {
    // ESC to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
            modal.classList.add('hidden');
        });
    }

    // Ctrl+R to refresh peers
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        refreshPeers();
    }
});

// ==================== CLEANUP ====================

window.addEventListener('beforeunload', () => {
    // Clear intervals
    Object.values(refreshIntervals).forEach(interval => {
        clearInterval(interval);
    });

    // Disconnect socket
    if (socket) {
        socket.disconnect();
    }
});
