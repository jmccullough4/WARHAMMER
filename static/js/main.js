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
let allPeers = [];
let allRoutes = [];
let allGroups = [];

const MAX_CHART_POINTS = 60;
const chartData = {
    labels: [],
    rx: [],
    tx: []
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
    fetchWarhammerStatus();
    fetchPeers();
    fetchRoutes();
    fetchGroups();

    // Set up refresh intervals
    refreshIntervals.systemInfo = setInterval(fetchSystemInfo, 5000);
    refreshIntervals.interfaces = setInterval(fetchNetworkInterfaces, 10000);
    refreshIntervals.services = setInterval(fetchServices, 30000);
    refreshIntervals.peers = setInterval(fetchPeers, 15000);
    refreshIntervals.warhammer = setInterval(fetchWarhammerStatus, 30000);
    refreshIntervals.routes = setInterval(fetchRoutes, 60000);

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

        // Update SBC info
        if (data.cpu_info) {
            const cpuShort = data.cpu_info.split('@')[0].trim();
            document.getElementById('sbcDetails').textContent = cpuShort;
        }

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

            // Make configurable interfaces clickable
            if (iface.configurable) {
                div.classList.add('configurable');
                div.onclick = () => openInterfaceConfig(iface);
            }

            div.innerHTML = `
                <div class="interface-info">
                    <div class="interface-name">${iface.name}${iface.configurable ? ' &#9881;' : ''}</div>
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

async function fetchWarhammerStatus() {
    try {
        const response = await fetch('/api/warhammer/status');
        const data = await response.json();

        const statusEl = document.getElementById('warhammerStatus');

        if (data.error) {
            statusEl.textContent = 'OFFLINE';
            statusEl.className = 'warhammer-status disconnected';
            return;
        }

        statusEl.textContent = 'CONNECTED';
        statusEl.className = 'warhammer-status connected';

        // Update details
        if (data.daemonVersion) {
            document.getElementById('whVersion').textContent = data.daemonVersion;
        }
        if (data.publicKey) {
            document.getElementById('whPubKey').textContent = data.publicKey.substring(0, 20) + '...';
        }
        if (data.fqdn) {
            document.getElementById('whFqdn').textContent = data.fqdn;
        }

    } catch (error) {
        console.error('Error fetching WARHAMMER status:', error);
        const statusEl = document.getElementById('warhammerStatus');
        statusEl.textContent = 'ERROR';
        statusEl.className = 'warhammer-status disconnected';
    }
}

async function fetchPeers() {
    try {
        const response = await fetch('/api/warhammer/peers');
        const peers = await response.json();

        if (peers.error) {
            addLog('WARN', `Peers fetch: ${peers.error}`);
            return;
        }

        allPeers = peers;
        renderPeers(peers);

        // Update map markers
        if (map) {
            updateMapMarkers(peers);
        }

        // Auto ping connected peers for latency
        const connectedPeers = peers.filter(p => p.connected);
        if (connectedPeers.length > 0 && connectedPeers.length <= 5) {
            // Only auto-ping if 5 or fewer peers
            pingAllPeers();
        }

    } catch (error) {
        console.error('Error fetching peers:', error);
    }
}

function renderPeers(peers) {
    const container = document.getElementById('peerList');
    container.innerHTML = '';

    // Sort peers: connected first (alphabetically), then disconnected (alphabetically)
    const sortedPeers = [...peers].sort((a, b) => {
        const aConnected = a.connected ? 1 : 0;
        const bConnected = b.connected ? 1 : 0;

        if (aConnected !== bConnected) {
            return bConnected - aConnected; // Connected first
        }

        // Then alphabetically by name
        const aName = (a.name || a.hostname || '').toLowerCase();
        const bName = (b.name || b.hostname || '').toLowerCase();
        return aName.localeCompare(bName);
    });

    const connectedCount = sortedPeers.filter(p => p.connected).length;
    document.getElementById('peerCount').textContent = connectedCount;
    document.getElementById('peerCounter').textContent = sortedPeers.length;

    sortedPeers.forEach(peer => {
        const isOnline = peer.connected;
        const div = document.createElement('div');
        div.className = `peer-item ${isOnline ? 'online' : 'offline'}`;
        div.onclick = () => showPeerDetails(peer);
        div.setAttribute('data-peer-name', (peer.name || peer.hostname || '').toLowerCase());
        div.setAttribute('data-peer-ip', peer.ip || '');

        const latencyHtml = peer.latency
            ? `<div class="peer-latency ${getLatencyClass(peer.latency)}">${peer.latency.toFixed(1)}ms</div>`
            : '';

        div.innerHTML = `
            <div class="peer-status-dot"></div>
            <div class="peer-info">
                <div class="peer-name">${peer.name || peer.hostname || 'Unknown'}</div>
                <div class="peer-ip">${peer.ip || '--'}</div>
            </div>
            ${latencyHtml}
        `;

        container.appendChild(div);
    });

    // Update latency chart
    updateLatencyChart(sortedPeers.filter(p => p.connected && p.latency));
}

async function fetchRoutes() {
    try {
        const response = await fetch('/api/warhammer/routes');
        const routes = await response.json();

        if (routes.error) {
            return;
        }

        allRoutes = routes;
        renderRoutes(routes);

    } catch (error) {
        console.error('Error fetching routes:', error);
    }
}

function renderRoutes(routes) {
    const container = document.getElementById('routeList');
    container.innerHTML = '';

    document.getElementById('routeCounter').textContent = routes.length;

    routes.forEach(route => {
        const div = document.createElement('div');
        div.className = 'route-item';

        const isPersistent = route.persistent;
        const canModify = !isPersistent;

        div.innerHTML = `
            <div class="route-info">
                <div class="route-network">${route.network || route.networkRange || route.network_id}</div>
                <div class="route-via">${route.description || 'No description'}${isPersistent ? ' (Persistent)' : ''}</div>
            </div>
            <div class="route-actions">
                ${canModify ? `
                    <button class="btn btn-sm ${route.enabled ? 'btn-success' : 'btn-secondary'}"
                            onclick="toggleRoute('${route.id}', ${!route.enabled}); event.stopPropagation();">
                        ${route.enabled ? 'ON' : 'OFF'}
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRoute('${route.id}'); event.stopPropagation();">
                        &#10005;
                    </button>
                ` : `
                    <span class="route-status ${route.enabled ? 'enabled' : 'disabled'}">
                        ${route.enabled ? 'ACTIVE' : 'INACTIVE'}
                    </span>
                    <span class="route-locked">&#128274;</span>
                `}
            </div>
        `;
        container.appendChild(div);
    });
}

async function fetchGroups() {
    try {
        const response = await fetch('/api/warhammer/groups');
        const groups = await response.json();

        if (!groups.error) {
            allGroups = groups;
        }
    } catch (error) {
        console.error('Error fetching groups:', error);
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
            animation: { duration: 300 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(18, 14, 12, 0.95)',
                    titleColor: '#ff6b35',
                    bodyColor: '#e8e0d8',
                    callbacks: {
                        label: (context) => context.dataset.label + ': ' + formatBytes(context.raw) + '/s'
                    }
                }
            },
            scales: {
                x: { display: false },
                y: {
                    display: true,
                    grid: { color: 'rgba(255, 107, 53, 0.1)' },
                    ticks: {
                        color: '#584838',
                        font: { family: 'Share Tech Mono', size: 10 },
                        callback: (value) => formatBytes(value)
                    }
                }
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
                backgroundColor: (context) => {
                    const value = context.raw;
                    if (value < 50) return 'rgba(48, 209, 88, 0.7)';
                    if (value < 100) return 'rgba(255, 176, 0, 0.7)';
                    return 'rgba(255, 59, 48, 0.7)';
                },
                borderColor: (context) => {
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
            animation: { duration: 300 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(18, 14, 12, 0.95)',
                    titleColor: '#ff6b35',
                    bodyColor: '#e8e0d8',
                    callbacks: {
                        label: (context) => context.raw.toFixed(1) + ' ms'
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#584838',
                        font: { family: 'Share Tech Mono', size: 9 },
                        maxRotation: 45
                    }
                },
                y: {
                    grid: { color: 'rgba(255, 107, 53, 0.1)' },
                    ticks: {
                        color: '#584838',
                        font: { family: 'Share Tech Mono', size: 10 },
                        callback: (value) => value + 'ms'
                    }
                }
            }
        }
    });
}

function updateLatencyChart(peers) {
    const labels = [];
    const data = [];

    peers.slice(0, 10).forEach(peer => {
        if (peer.latency) {
            const name = peer.name || peer.hostname || peer.ip;
            // Truncate long names
            labels.push(name.length > 12 ? name.substring(0, 10) + '..' : name);
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
        center: [-98.5795, 39.8283],
        zoom: 3,
        attributionControl: false
    });

    map.addControl(new mapboxgl.NavigationControl(), 'top-right');

    map.on('load', () => {
        addLog('INFO', 'Map initialized');
    });
}

function getNetworkName(peer) {
    // Get short network name - not FQDN, never show "netbird"
    let name = peer.name || peer.hostname || '';

    // Remove domain suffix if present
    if (name.includes('.')) {
        name = name.split('.')[0];
    }

    // Never show netbird-related names
    if (name.toLowerCase().includes('netbird')) {
        name = peer.ip || 'Unknown';
    }

    return name || peer.ip || 'Unknown';
}

function updateMapMarkers(peers) {
    // Remove old peer markers (keep local node)
    Object.keys(peerMarkers).forEach(key => {
        if (key !== 'local-node') {
            peerMarkers[key].remove();
            delete peerMarkers[key];
        }
    });

    const bounds = new mapboxgl.LngLatBounds();
    let hasValidCoords = false;

    peers.forEach(peer => {
        // Check for GPS coordinates - try multiple possible field names
        let lat = peer.location?.latitude || peer.geoLocation?.latitude || peer.latitude;
        let lng = peer.location?.longitude || peer.geoLocation?.longitude || peer.longitude;

        // Also check city_name with country for geocoding hint
        if (!lat && !lng && peer.city_name && peer.country_code) {
            // Could implement geocoding here if needed
            return;
        }

        if (lat && lng && !isNaN(lat) && !isNaN(lng)) {
            hasValidCoords = true;
            const isOnline = peer.connected;
            const networkName = getNetworkName(peer);

            // Create custom marker element
            const el = document.createElement('div');
            el.className = `map-marker ${isOnline ? 'online' : 'offline'}`;
            el.innerHTML = `
                <div class="marker-dot"></div>
                <div class="marker-pulse"></div>
                <div class="marker-label">${networkName}</div>
            `;
            el.title = networkName;

            // Create popup
            const popup = new mapboxgl.Popup({ offset: 25 }).setHTML(`
                <div class="map-popup">
                    <strong>${networkName}</strong>
                    <div>${peer.ip || '--'}</div>
                    <div class="popup-status ${isOnline ? 'online' : 'offline'}">
                        ${isOnline ? 'ONLINE' : 'OFFLINE'}
                    </div>
                    ${peer.latency ? `<div class="popup-latency">${peer.latency.toFixed(1)}ms</div>` : ''}
                </div>
            `);

            const marker = new mapboxgl.Marker(el)
                .setLngLat([lng, lat])
                .setPopup(popup)
                .addTo(map);

            peerMarkers[peer.id || peer.ip] = marker;
            bounds.extend([lng, lat]);
        }
    });

    // Fit map to bounds if we have markers
    if (hasValidCoords && Object.keys(peerMarkers).length > 0) {
        // Don't auto-fit, let user control the view
    }
}

function fitMapToPeers() {
    if (!map || Object.keys(peerMarkers).length === 0) return;

    const bounds = new mapboxgl.LngLatBounds();
    Object.values(peerMarkers).forEach(marker => {
        bounds.extend(marker.getLngLat());
    });

    map.fitBounds(bounds, { padding: 50, maxZoom: 10 });
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

// ==================== PING ====================

async function pingAllPeers() {
    const connectedPeers = allPeers.filter(p => p.connected && p.ip);

    if (connectedPeers.length === 0) {
        addLog('WARN', 'No connected peers to ping');
        return;
    }

    addLog('INFO', `Pinging ${connectedPeers.length} peers...`);

    for (const peer of connectedPeers) {
        try {
            const response = await fetch(`/api/ping/${peer.ip}`);
            const data = await response.json();

            if (data.latency) {
                // Update peer in allPeers array
                const idx = allPeers.findIndex(p => p.ip === peer.ip);
                if (idx !== -1) {
                    allPeers[idx].latency = data.latency;
                }
            }
        } catch (error) {
            console.error(`Ping failed for ${peer.ip}:`, error);
        }
    }

    // Re-render peers with updated latency
    renderPeers(allPeers);
    addLog('SUCCESS', 'Ping sweep completed');
}

async function pingPeer(ip) {
    if (!ip) return;

    addLog('INFO', `Pinging ${ip}...`);

    try {
        const response = await fetch(`/api/ping/${ip}`);
        const data = await response.json();

        if (data.status === 'online') {
            addLog('SUCCESS', `Ping to ${ip}: ${data.latency.toFixed(1)}ms`);

            // Update peer latency
            const idx = allPeers.findIndex(p => p.ip === ip);
            if (idx !== -1) {
                allPeers[idx].latency = data.latency;
                renderPeers(allPeers);
            }
        } else {
            addLog('WARN', `Ping to ${ip}: ${data.status}`);
        }
    } catch (error) {
        addLog('ERROR', `Ping failed: ${error.message}`);
    }
}

// ==================== ROUTES ====================

function openAddRouteModal() {
    // Populate peer dropdown
    const select = document.getElementById('routePeer');
    select.innerHTML = '<option value="">-- Select Peer --</option>';

    allPeers.filter(p => p.connected).forEach(peer => {
        const option = document.createElement('option');
        option.value = peer.id;
        option.textContent = peer.name || peer.hostname || peer.ip;
        select.appendChild(option);
    });

    document.getElementById('addRouteModal').classList.remove('hidden');
}

function closeAddRouteModal() {
    document.getElementById('addRouteModal').classList.add('hidden');
}

async function submitAddRoute() {
    const network = document.getElementById('routeNetwork').value.trim();
    const description = document.getElementById('routeDescription').value.trim();
    const peerId = document.getElementById('routePeer').value;
    const metric = parseInt(document.getElementById('routeMetric').value) || 9999;
    const masquerade = document.getElementById('routeMasquerade').checked;
    const enabled = document.getElementById('routeEnabled').checked;

    if (!network) {
        addLog('ERROR', 'Network CIDR is required');
        return;
    }

    try {
        const response = await fetch('/api/warhammer/routes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                network,
                description,
                peer: peerId,
                metric,
                masquerade,
                enabled
            })
        });

        const data = await response.json();

        if (response.ok) {
            addLog('SUCCESS', `Route ${network} added`);
            closeAddRouteModal();
            fetchRoutes();
        } else {
            addLog('ERROR', data.error || 'Failed to add route');
        }
    } catch (error) {
        addLog('ERROR', `Add route failed: ${error.message}`);
    }
}

async function toggleRoute(routeId, enabled) {
    try {
        const route = allRoutes.find(r => r.id === routeId);
        if (!route) return;

        const response = await fetch(`/api/warhammer/routes/${routeId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...route, enabled })
        });

        if (response.ok) {
            addLog('SUCCESS', `Route ${enabled ? 'enabled' : 'disabled'}`);
            fetchRoutes();
        } else {
            const data = await response.json();
            addLog('ERROR', data.error || 'Failed to toggle route');
        }
    } catch (error) {
        addLog('ERROR', `Toggle route failed: ${error.message}`);
    }
}

async function deleteRoute(routeId) {
    showConfirm('DELETE ROUTE', 'Are you sure you want to delete this route?', async () => {
        try {
            const response = await fetch(`/api/warhammer/routes/${routeId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                addLog('SUCCESS', 'Route deleted');
                fetchRoutes();
            } else {
                const data = await response.json();
                addLog('ERROR', data.error || 'Failed to delete route');
            }
        } catch (error) {
            addLog('ERROR', `Delete route failed: ${error.message}`);
        }
    });
}

// ==================== INTERFACE CONFIG ====================

function openInterfaceConfig(iface) {
    const modal = document.getElementById('interfaceModal');
    const content = document.getElementById('interfaceModalContent');

    const ipList = iface.addresses
        .filter(a => a.type === 'ipv4')
        .map(a => `
            <div class="ip-item">
                <span>${a.address}</span>
                <button class="btn btn-sm btn-danger" onclick="removeInterfaceIP('${iface.name}', '${a.address}')">&#10005;</button>
            </div>
        `).join('') || '<div class="ip-item">No IPv4 addresses</div>';

    content.innerHTML = `
        <div class="interface-config">
            <h3>${iface.name}</h3>
            <div class="info-row">
                <span class="info-label">Status:</span>
                <span class="info-value ${iface.is_up ? 'online' : 'offline'}">${iface.is_up ? 'UP' : 'DOWN'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Speed:</span>
                <span class="info-value">${iface.speed || 'Unknown'} Mbps</span>
            </div>

            <h4>IP Addresses</h4>
            <div class="ip-list">${ipList}</div>

            <div class="add-ip-form">
                <input type="text" id="newIP" class="input" placeholder="192.168.1.100">
                <button class="btn btn-primary btn-sm" onclick="addInterfaceIP('${iface.name}')">ADD IP</button>
            </div>
        </div>
    `;

    modal.classList.remove('hidden');
}

function closeInterfaceModal() {
    document.getElementById('interfaceModal').classList.add('hidden');
}

async function addInterfaceIP(iface) {
    const ip = document.getElementById('newIP').value.trim();
    if (!ip) return;

    try {
        const response = await fetch(`/api/interface/${iface}/ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });

        const data = await response.json();

        if (response.ok) {
            addLog('SUCCESS', `Added IP ${ip} to ${iface}`);
            closeInterfaceModal();
            fetchNetworkInterfaces();
        } else {
            addLog('ERROR', data.error || 'Failed to add IP');
        }
    } catch (error) {
        addLog('ERROR', `Add IP failed: ${error.message}`);
    }
}

async function removeInterfaceIP(iface, ip) {
    showConfirm('REMOVE IP', `Remove ${ip} from ${iface}?`, async () => {
        try {
            const response = await fetch(`/api/interface/${iface}/ip`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });

            const data = await response.json();

            if (response.ok) {
                addLog('SUCCESS', `Removed IP ${ip} from ${iface}`);
                closeInterfaceModal();
                fetchNetworkInterfaces();
            } else {
                addLog('ERROR', data.error || 'Failed to remove IP');
            }
        } catch (error) {
            addLog('ERROR', `Remove IP failed: ${error.message}`);
        }
    });
}

// ==================== GAUGES ====================

function updateGauge(type, percent) {
    const fill = document.getElementById(`${type}GaugeFill`);
    const value = document.getElementById(`${type}GaugeValue`);

    const offset = 283 - (283 * percent / 100);
    fill.style.strokeDashoffset = offset;

    fill.classList.remove('warning', 'danger');
    if (percent > 80) {
        fill.classList.add('danger');
    } else if (percent > 60) {
        fill.classList.add('warning');
    }

    value.textContent = `${percent.toFixed(0)}%`;
}

// ==================== UI INTERACTIONS ====================

function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.toggle('collapsed');
    }
}

function filterPeers() {
    const search = document.getElementById('peerSearch').value.toLowerCase();
    const items = document.querySelectorAll('.peer-item');

    items.forEach(item => {
        const name = item.getAttribute('data-peer-name') || '';
        const ip = item.getAttribute('data-peer-ip') || '';

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
                <span class="info-value">${peer.ip || '--'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Status:</span>
                <span class="info-value ${peer.connected ? 'online' : 'offline'}">${peer.connected ? 'Connected' : 'Disconnected'}</span>
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
            ${peer.latency ? `
            <div class="info-row">
                <span class="info-label">Latency:</span>
                <span class="info-value ${getLatencyClass(peer.latency)}">${peer.latency.toFixed(1)} ms</span>
            </div>
            ` : ''}
            ${peer.groups ? `
            <div class="info-row">
                <span class="info-label">Groups:</span>
                <span class="info-value">${peer.groups.map(g => g.name || g).join(', ')}</span>
            </div>
            ` : ''}
            ${peer.city_name ? `
            <div class="info-row">
                <span class="info-label">Location:</span>
                <span class="info-value">${peer.city_name}${peer.country_code ? ', ' + peer.country_code : ''}</span>
            </div>
            ` : ''}
        </div>
        <div class="btn-group" style="margin-top: 15px;">
            <button class="btn btn-primary" onclick="pingPeer('${peer.ip}')">PING</button>
            <button class="btn btn-secondary" onclick="closePeerModal()">CLOSE</button>
        </div>
    `;

    modal.classList.remove('hidden');
}

function closePeerModal() {
    document.getElementById('peerModal').classList.add('hidden');
}

// ==================== SETTINGS ====================

function openSettingsModal() {
    document.getElementById('settingsModal').classList.remove('hidden');
}

function closeSettingsModal() {
    document.getElementById('settingsModal').classList.add('hidden');
}

function showSettingsTab(tab) {
    document.querySelectorAll('.settings-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.settings-tab').forEach(el => el.classList.remove('active'));

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

    logs.push({ time: timeStr, level, message });
    if (logs.length > 100) {
        logs.shift();
        if (container.firstChild) {
            container.removeChild(container.firstChild);
        }
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
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
            modal.classList.add('hidden');
        });
    }

    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        refreshPeers();
    }
});

// ==================== SYSTEM UPGRADE ====================

let upgradePollingInterval = null;
let currentUpgradeType = null;

function openUpgradeModal() {
    document.getElementById('upgradeModal').classList.remove('hidden');
    document.getElementById('upgradeInitial').classList.remove('hidden');
    document.getElementById('upgradeProgress').classList.add('hidden');
    document.getElementById('upgradeComplete').classList.add('hidden');
    document.getElementById('upgradeFailed').classList.add('hidden');
    document.getElementById('upgradeRestarting').classList.add('hidden');
    document.getElementById('upgradeModalClose').style.display = '';
}

function closeUpgradeModal() {
    if (upgradePollingInterval) {
        clearInterval(upgradePollingInterval);
        upgradePollingInterval = null;
    }
    document.getElementById('upgradeModal').classList.add('hidden');
    // Reset upgrade status on server
    fetch('/api/system/upgrade/reset', { method: 'POST' });
}

async function startUpgrade(type = 'full') {
    currentUpgradeType = type;
    document.getElementById('upgradeInitial').classList.add('hidden');
    document.getElementById('upgradeProgress').classList.remove('hidden');
    document.getElementById('upgradeModalClose').style.display = 'none';

    try {
        const response = await fetch('/api/system/upgrade', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });
        const data = await response.json();

        if (response.ok) {
            addLog('INFO', `${type.toUpperCase()} upgrade started`);
            startUpgradePolling();
        } else {
            addLog('ERROR', data.error || 'Failed to start upgrade');
            showUpgradeError(data.error || 'Failed to start upgrade');
        }
    } catch (error) {
        addLog('ERROR', 'Upgrade failed: ' + error.message);
        showUpgradeError(error.message);
    }
}

function startUpgradePolling() {
    upgradePollingInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/system/upgrade/status');
            const status = await response.json();
            updateUpgradeUI(status);

            if (!status.running) {
                clearInterval(upgradePollingInterval);
                upgradePollingInterval = null;

                if (status.completed) {
                    showUpgradeComplete(status.reboot_required, status.upgrade_type);
                } else if (status.error) {
                    showUpgradeError(status.error);
                }
            }
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, 1000);
}

function updateUpgradeUI(status) {
    document.getElementById('upgradeStage').textContent = status.stage || 'Processing...';
    document.getElementById('upgradeProgressFill').style.width = `${status.progress}%`;

    const logContainer = document.getElementById('upgradeLog');
    logContainer.innerHTML = status.log.map(entry => {
        let cssClass = '';
        if (entry.includes('[INFO]')) cssClass = 'info';
        else if (entry.includes('[OK]')) cssClass = 'ok';
        else if (entry.includes('[WARN]')) cssClass = 'warn';
        else if (entry.includes('[ERROR]')) cssClass = 'error';
        else if (entry.includes('[SUCCESS]')) cssClass = 'success';

        return `<div class="upgrade-log-entry ${cssClass}">${entry}</div>`;
    }).join('');
    logContainer.scrollTop = logContainer.scrollHeight;
}

function showUpgradeComplete(rebootRequired, upgradeType) {
    document.getElementById('upgradeProgress').classList.add('hidden');
    document.getElementById('upgradeComplete').classList.remove('hidden');
    document.getElementById('upgradeModalClose').style.display = '';

    const msgEl = document.getElementById('upgradeCompleteMsg');
    const actionsEl = document.getElementById('upgradeCompleteActions');

    if (rebootRequired) {
        // Full system upgrade with kernel update - show reboot option
        msgEl.textContent = 'A system reboot is recommended to complete the kernel update.';
        actionsEl.innerHTML = `
            <button class="btn btn-warning" onclick="confirmReboot()">REBOOT NOW</button>
            <button class="btn btn-secondary" onclick="closeUpgradeModal()">LATER</button>
        `;
    } else if (upgradeType === 'ui') {
        // UI-only upgrade - show restart app option
        msgEl.textContent = 'Restart the application to apply updates.';
        actionsEl.innerHTML = `
            <button class="btn btn-primary" onclick="restartApp()">RESTART APP</button>
            <button class="btn btn-secondary" onclick="closeUpgradeModal()">LATER</button>
        `;
    } else {
        // Full system upgrade, no reboot needed
        msgEl.textContent = 'All updates applied successfully.';
        actionsEl.innerHTML = `
            <button class="btn btn-primary" onclick="restartApp()">RESTART APP</button>
            <button class="btn btn-secondary" onclick="closeUpgradeModal()">CLOSE</button>
        `;
    }

    addLog('SUCCESS', 'Upgrade completed');
}

async function restartApp() {
    document.getElementById('upgradeComplete').classList.add('hidden');
    document.getElementById('upgradeRestarting').classList.remove('hidden');
    document.getElementById('upgradeModalClose').style.display = 'none';

    addLog('INFO', 'Restarting application...');

    try {
        await fetch('/api/system/restart-app', { method: 'POST' });

        // Wait and then start polling for reconnection
        setTimeout(() => {
            pollForReconnection();
        }, 2000);
    } catch (error) {
        // Expected - server is restarting
        setTimeout(() => {
            pollForReconnection();
        }, 2000);
    }
}

function pollForReconnection() {
    let attempts = 0;
    const maxAttempts = 30;

    const checkInterval = setInterval(async () => {
        attempts++;
        try {
            const response = await fetch('/api/version', { cache: 'no-store' });
            if (response.ok) {
                clearInterval(checkInterval);
                addLog('SUCCESS', 'Application restarted successfully');
                // Reload the page to get fresh content
                window.location.reload();
            }
        } catch (error) {
            // Still waiting for server
            if (attempts >= maxAttempts) {
                clearInterval(checkInterval);
                document.getElementById('upgradeRestarting').innerHTML = `
                    <div style="text-align: center;">
                        <span style="font-size: 40px;">&#9888;</span>
                        <h3 style="color: var(--accent-warning);">Restart Taking Longer Than Expected</h3>
                        <p style="color: var(--text-muted);">Please refresh the page manually.</p>
                        <button class="btn btn-primary" onclick="window.location.reload()" style="margin-top: 15px;">REFRESH PAGE</button>
                    </div>
                `;
            }
        }
    }, 1000);
}

function showUpgradeError(error) {
    document.getElementById('upgradeProgress').classList.add('hidden');
    document.getElementById('upgradeFailed').classList.remove('hidden');
    document.getElementById('upgradeError').textContent = error;
    document.getElementById('upgradeModalClose').style.display = '';
}

function retryUpgrade() {
    document.getElementById('upgradeFailed').classList.add('hidden');
    startUpgrade(currentUpgradeType || 'full');
}

// Listen for upgrade progress via websocket
if (typeof socket !== 'undefined' && socket) {
    socket.on('upgrade_progress', (data) => {
        updateUpgradeUI(data);
    });
}

// ==================== RESIZABLE PANELS ====================

let resizeState = {
    active: false,
    section: null,
    startY: 0,
    startHeight: 0
};

function initResizablePanels() {
    const sections = document.querySelectorAll('.panel-section .section-content');

    sections.forEach(content => {
        const section = content.closest('.panel-section');
        if (!section) return;

        // Add resize handle
        const handle = document.createElement('div');
        handle.className = 'resize-handle';
        section.appendChild(handle);
        section.classList.add('resizable');

        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            resizeState.active = true;
            resizeState.section = content;
            resizeState.startY = e.clientY;
            resizeState.startHeight = content.offsetHeight;
            handle.classList.add('active');
            document.body.style.cursor = 'ns-resize';
        });
    });

    document.addEventListener('mousemove', (e) => {
        if (!resizeState.active) return;

        const delta = e.clientY - resizeState.startY;
        const newHeight = Math.max(50, Math.min(500, resizeState.startHeight + delta));
        resizeState.section.style.maxHeight = newHeight + 'px';
    });

    document.addEventListener('mouseup', () => {
        if (resizeState.active) {
            resizeState.active = false;
            document.body.style.cursor = '';
            document.querySelectorAll('.resize-handle.active').forEach(h => h.classList.remove('active'));
        }
    });
}

// Initialize resizable panels after DOM is ready
document.addEventListener('DOMContentLoaded', initResizablePanels);

// ==================== ENHANCED MAP WITH LOCAL NODE ====================

let localNodeData = null;

async function fetchLocalNodeInfo() {
    try {
        const response = await fetch('/api/warhammer/status');
        if (response.ok) {
            localNodeData = await response.json();

            // Update map with local node
            if (map && localNodeData) {
                updateMapWithLocalNode();
            }
        }
    } catch (error) {
        console.error('Failed to fetch local node info:', error);
    }
}

function updateMapWithLocalNode() {
    if (!map || !localNodeData) return;

    // Remove existing local node marker
    if (peerMarkers['local-node']) {
        peerMarkers['local-node'].remove();
        delete peerMarkers['local-node'];
    }

    // Check for local node location (from netbird status)
    const localIP = localNodeData.ip || localNodeData.localPeerState?.ip;
    const fqdn = localNodeData.fqdn || localNodeData.localPeerState?.fqdn;

    // Get network name for local node (same format as peers)
    let localName = fqdn || CONFIG.hostname || 'Local';
    if (localName.includes('.')) {
        localName = localName.split('.')[0];
    }
    if (localName.toLowerCase().includes('netbird')) {
        localName = CONFIG.hostname || localIP || 'Local';
    }

    // Try to get location - prioritize GPS data from gpsd
    let lat = null;
    let lng = null;
    let gpsInfo = null;

    // First try GPS data from gpsd (most accurate, real-time)
    if (localNodeData.gps && localNodeData.gps.latitude && localNodeData.gps.longitude) {
        lat = localNodeData.gps.latitude;
        lng = localNodeData.gps.longitude;
        gpsInfo = {
            altitude: localNodeData.gps.altitude,
            speed: localNodeData.gps.speed,
            heading: localNodeData.gps.heading,
            satellites: localNodeData.gps.satellites,
            fix_type: localNodeData.gps.fix_type
        };
        console.log('Using GPS data from gpsd:', lat, lng);
    }
    // Fallback to netbird location data
    else {
        lat = localNodeData.location?.latitude ||
              localNodeData.localPeerState?.location?.latitude ||
              localNodeData.geoNameID?.latitude;
        lng = localNodeData.location?.longitude ||
              localNodeData.localPeerState?.location?.longitude ||
              localNodeData.geoNameID?.longitude;
    }

    // If we have valid coordinates, add local node marker
    // Local node uses cyan/blue color (different from green peers) - no label needed
    if (lat && lng && !isNaN(lat) && !isNaN(lng)) {
        const el = document.createElement('div');
        el.className = 'map-marker local-node online';
        el.innerHTML = `
            <div class="marker-dot"></div>
            <div class="marker-pulse"></div>
        `;
        el.title = `${localName} (You)`;

        // Build popup content with GPS info if available
        let gpsDetails = '';
        if (gpsInfo) {
            const fixTypes = ['No Fix', 'No Fix', '2D Fix', '3D Fix'];
            gpsDetails = `
                <div style="margin-top: 8px; border-top: 1px solid #333; padding-top: 6px; font-size: 10px;">
                    <div>&#128225; GPS Fix: ${fixTypes[gpsInfo.fix_type] || 'Unknown'}</div>
                    <div>&#128752; Satellites: ${gpsInfo.satellites || 0}</div>
                    ${gpsInfo.altitude ? `<div>&#9650; Alt: ${gpsInfo.altitude.toFixed(1)}m</div>` : ''}
                    ${gpsInfo.speed ? `<div>&#128663; Speed: ${(gpsInfo.speed * 3.6).toFixed(1)} km/h</div>` : ''}
                    ${gpsInfo.heading ? `<div>&#129517; Heading: ${gpsInfo.heading.toFixed(0)}°</div>` : ''}
                </div>
            `;
        }

        const popup = new mapboxgl.Popup({ offset: 25 }).setHTML(`
            <div class="map-popup">
                <strong style="color: #00d4ff;">${localName}</strong>
                <div style="font-size: 9px; color: #00d4ff; margin-bottom: 4px;">(This Node)</div>
                <div>${localIP || '--'}</div>
                <div style="font-size: 9px; color: #666; margin-top: 4px;">
                    ${lat.toFixed(6)}, ${lng.toFixed(6)}
                </div>
                <div class="popup-status online">ONLINE</div>
                ${gpsDetails}
            </div>
        `);

        const marker = new mapboxgl.Marker(el)
            .setLngLat([lng, lat])
            .setPopup(popup)
            .addTo(map);

        peerMarkers['local-node'] = marker;

        // Log success
        addLog('INFO', `Local node GPS: ${lat.toFixed(4)}, ${lng.toFixed(4)}`);
    } else {
        console.log('No GPS coordinates available for local node');
    }
}

// Override the updateMapMarkers to also update local node
const originalUpdateMapMarkers = updateMapMarkers;
function updateMapMarkersEnhanced(peers) {
    // Call original function
    originalUpdateMapMarkers(peers);

    // Also update local node
    updateMapWithLocalNode();

    // Show placeholder if no markers
    const container = document.getElementById('mapContainer');
    if (container && Object.keys(peerMarkers).length === 0) {
        if (!container.querySelector('.map-placeholder')) {
            // Map exists but no markers - peers may not have location data
            console.log('No peers with GPS data available for map display');
        }
    }
}

// Replace the global updateMapMarkers
if (typeof updateMapMarkers !== 'undefined') {
    window.updateMapMarkers = updateMapMarkersEnhanced;
}

// Fetch local node info on init and periodically
document.addEventListener('DOMContentLoaded', () => {
    fetchLocalNodeInfo();
    setInterval(fetchLocalNodeInfo, 10000); // Refresh every 10 seconds for GPS updates
});

// ==================== CONTEXT MENU & SPEEDTEST ====================

let contextMenuPeer = null;
let speedtestPollingInterval = null;

// Context menu for peer items
document.addEventListener('contextmenu', (e) => {
    const peerItem = e.target.closest('.peer-item');
    if (peerItem) {
        e.preventDefault();

        // Find the peer data
        const peerIP = peerItem.getAttribute('data-peer-ip');
        const peer = allPeers.find(p => p.ip === peerIP);

        if (peer && peer.connected) {
            contextMenuPeer = peer;

            const menu = document.getElementById('peerContextMenu');
            menu.style.left = `${e.clientX}px`;
            menu.style.top = `${e.clientY}px`;
            menu.classList.remove('hidden');
        }
    }
});

// Hide context menu on click elsewhere
document.addEventListener('click', () => {
    const menu = document.getElementById('peerContextMenu');
    if (menu) {
        menu.classList.add('hidden');
    }
});

function runSpeedtest() {
    if (!contextMenuPeer || !contextMenuPeer.ip) {
        addLog('ERROR', 'No peer selected for speedtest');
        return;
    }

    openSpeedtestModal(contextMenuPeer);
}

function showPeerDetailsFromContext() {
    if (contextMenuPeer) {
        showPeerDetails(contextMenuPeer);
    }
}

function openSpeedtestModal(peer) {
    const modal = document.getElementById('speedtestModal');
    const targetIP = document.getElementById('speedtestTargetIP');
    const peerName = getNetworkName(peer);

    targetIP.textContent = `${peerName} (${peer.ip})`;

    // Reset UI
    document.getElementById('downloadSpeed').textContent = '0';
    document.getElementById('uploadSpeed').textContent = '0';
    document.getElementById('downloadGaugeFill').style.strokeDashoffset = '339.292';
    document.getElementById('uploadGaugeFill').style.strokeDashoffset = '339.292';
    document.getElementById('speedtestProgressFill').style.width = '0%';
    document.getElementById('speedtestStatus').textContent = 'Connecting...';
    document.getElementById('speedtestResults').classList.add('hidden');
    document.getElementById('speedtestError').classList.add('hidden');
    document.getElementById('speedtestModalClose').style.display = 'none';

    modal.classList.remove('hidden');

    // Start the test
    startSpeedtest(peer.ip);
}

function closeSpeedtestModal() {
    document.getElementById('speedtestModal').classList.add('hidden');
    if (speedtestPollingInterval) {
        clearInterval(speedtestPollingInterval);
        speedtestPollingInterval = null;
    }
}

async function startSpeedtest(targetIP) {
    try {
        const response = await fetch(`/api/iperf/${targetIP}`, { method: 'POST' });
        const data = await response.json();

        if (response.ok) {
            addLog('INFO', `Speedtest started to ${targetIP}`);
            startSpeedtestPolling();
        } else {
            showSpeedtestError(data.error || 'Failed to start speedtest');
        }
    } catch (error) {
        showSpeedtestError(error.message);
    }
}

function startSpeedtestPolling() {
    let progressPercent = 0;

    speedtestPollingInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/iperf/status');
            const status = await response.json();

            if (status.running) {
                // Update progress
                progressPercent = Math.min(progressPercent + 10, 95);
                document.getElementById('speedtestProgressFill').style.width = `${progressPercent}%`;
                document.getElementById('speedtestStatus').textContent = 'Testing throughput...';

                // Update gauges with latest result
                if (status.results && status.results.length > 0) {
                    const latest = status.results[status.results.length - 1];
                    const speedMbps = (latest.bits_per_second / 1000000).toFixed(1);
                    updateSpeedGauge('download', speedMbps);
                }
            } else {
                clearInterval(speedtestPollingInterval);
                speedtestPollingInterval = null;

                if (status.error) {
                    showSpeedtestError(status.error);
                } else if (status.final) {
                    showSpeedtestResults(status.final);
                }
            }
        } catch (error) {
            console.error('Speedtest polling error:', error);
        }
    }, 500);
}

function updateSpeedGauge(type, speedMbps) {
    const maxSpeed = 1000; // Max gauge at 1 Gbps
    const percent = Math.min(parseFloat(speedMbps) / maxSpeed * 100, 100);
    const circumference = 339.292;
    const offset = circumference - (circumference * percent / 100);

    document.getElementById(`${type}Speed`).textContent = speedMbps;
    document.getElementById(`${type}GaugeFill`).style.strokeDashoffset = offset;
}

function showSpeedtestResults(final) {
    document.getElementById('speedtestProgressFill').style.width = '100%';
    document.getElementById('speedtestStatus').textContent = 'Test complete!';
    document.getElementById('speedtestModalClose').style.display = '';

    // Update final speeds
    const downloadMbps = (final.received.bits_per_second / 1000000).toFixed(1);
    const uploadMbps = (final.sent.bits_per_second / 1000000).toFixed(1);

    updateSpeedGauge('download', downloadMbps);
    updateSpeedGauge('upload', uploadMbps);

    // Show results
    const totalBytes = final.sent.bytes + final.received.bytes;
    document.getElementById('resultDataTransferred').textContent = formatBytes(totalBytes);
    document.getElementById('resultRetransmits').textContent = final.sent.retransmits || '0';
    document.getElementById('speedtestResults').classList.remove('hidden');

    addLog('SUCCESS', `Speedtest: ${downloadMbps} Mbps down, ${uploadMbps} Mbps up`);
}

function showSpeedtestError(error) {
    document.getElementById('speedtestStatus').textContent = 'Test failed';
    document.getElementById('speedtestModalClose').style.display = '';
    document.getElementById('speedtestErrorMsg').textContent = error;
    document.getElementById('speedtestError').classList.remove('hidden');

    addLog('ERROR', `Speedtest failed: ${error}`);
}

// Listen for iperf progress via websocket
if (typeof socket !== 'undefined' && socket) {
    socket.on('iperf_progress', (data) => {
        if (data.results && data.results.length > 0) {
            const latest = data.results[data.results.length - 1];
            const speedMbps = (latest.bits_per_second / 1000000).toFixed(1);
            updateSpeedGauge('download', speedMbps);
        }
    });

    socket.on('iperf_complete', (data) => {
        if (speedtestPollingInterval) {
            clearInterval(speedtestPollingInterval);
            speedtestPollingInterval = null;
        }

        if (data.error) {
            showSpeedtestError(data.error);
        } else if (data.final) {
            showSpeedtestResults(data.final);
        }
    });
}

// ==================== CLEANUP ====================

window.addEventListener('beforeunload', () => {
    Object.values(refreshIntervals).forEach(interval => clearInterval(interval));
    if (upgradePollingInterval) clearInterval(upgradePollingInterval);
    if (socket) socket.disconnect();
});
