#!/usr/bin/env python3
"""
WARHAMMER - Network Overlay Management System
A stunning web interface for WARHAMMER network overlay management
and SBC control.
"""

import os
import sys
import json
import time
import subprocess
import threading
import requests
import psutil
import socket
import ipaddress
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit

# Configuration from environment
WARHAMMER_NAME = os.environ.get('WARHAMMER_NAME', socket.gethostname())
MANAGEMENT_INTERFACE_1 = os.environ.get('MANAGEMENT_INTERFACE_1', '100.74.0.154')
MANAGEMENT_INTERFACE_2 = os.environ.get('MANAGEMENT_INTERFACE_2', '18.18.18.18')
MANAGEMENT_INTERFACE_3 = os.environ.get('MANAGEMENT_INTERFACE_3', '10.109.100.1')
BRIDGE_INTERFACE = os.environ.get('BRIDGE_INTERFACE', 'br0')
WWAN_INTERFACE = os.environ.get('WWAN_INTERFACE', 'wwan0')
WIFI_INTERFACE = os.environ.get('WIFI_INTERFACE', 'wlo1')
PORT_1_INTERFACE = os.environ.get('PORT_1_INTERFACE', 'enp87s0')
PORT_2_INTERFACE = os.environ.get('PORT_2_INTERFACE', 'enp86s0')
BRIDGED_CIDR = os.environ.get('BRIDGED_CIDR', f'{MANAGEMENT_INTERFACE_3}/24')
WARHAMMER_DOMAIN = os.environ.get('NETBIRD_DOMAIN', 'demo.crabsthatgrab.com')
WARHAMMER_TOKEN = os.environ.get('NETBIRD_TOKEN', '')
MAPBOX_TOKEN = os.environ.get('MAPBOX_TOKEN', '')
BASE_NETPLAN = os.environ.get('BASE_NETPLAN', '/etc/netplan/01-network-manager-all.yaml')

# Interfaces to hide from the UI
HIDDEN_INTERFACES = ['lo', 'virbr0', 'virbr0-nic', 'docker0']

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'warhammer-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Default credentials (should be changed in production)
USERS = {
    'admin': 'warhammer',
    'operator': 'operator123'
}

# Cache for peer latency data
peer_latency_cache = {}
latency_history = {}  # {peer_ip: [latency_values]}
MAX_LATENCY_HISTORY = 30

# ==================== AUTHENTICATION ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if username in USERS and USERS[username] == password:
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Access denied.'

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('main.html',
        warhammer_name=WARHAMMER_NAME,
        username=session.get('username', 'operator'),
        warhammer_domain=WARHAMMER_DOMAIN,
        mapbox_token=MAPBOX_TOKEN,
        management_ip=MANAGEMENT_INTERFACE_1
    )

# ==================== HELPER FUNCTIONS ====================

def get_api_headers():
    """Get headers for WARHAMMER API calls"""
    return {
        'Authorization': f'Token {WARHAMMER_TOKEN}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

def is_persistent_route(route):
    """Check if a route is marked as persistent (cannot be modified)"""
    description = route.get('description', '') or ''
    return 'persistent' in description.lower()

# ==================== API ENDPOINTS ====================

@app.route('/api/system/info')
@login_required
def get_system_info():
    """Get comprehensive system information"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Get temperatures if available
        temps = {}
        try:
            temp_data = psutil.sensors_temperatures()
            for name, entries in temp_data.items():
                if entries:
                    temps[name] = entries[0].current
        except:
            pass

        # Get uptime
        uptime_seconds = time.time() - psutil.boot_time()
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))

        # Get CPU info
        cpu_info = "Unknown"
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line:
                        cpu_info = line.split(':')[1].strip()
                        break
        except:
            pass

        return jsonify({
            'hostname': WARHAMMER_NAME,
            'cpu_percent': cpu_percent,
            'cpu_info': cpu_info,
            'memory_percent': memory.percent,
            'memory_used': memory.used,
            'memory_total': memory.total,
            'disk_percent': disk.percent,
            'disk_used': disk.used,
            'disk_total': disk.total,
            'temperatures': temps,
            'uptime': uptime_str,
            'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/interfaces')
@login_required
def get_network_interfaces():
    """Get all network interfaces with their status (excluding hidden ones)"""
    try:
        interfaces = []
        net_io = psutil.net_io_counters(pernic=True)
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        for iface, addrs in net_if_addrs.items():
            # Skip hidden interfaces
            if iface in HIDDEN_INTERFACES:
                continue

            info = {
                'name': iface,
                'addresses': [],
                'is_up': False,
                'speed': 0,
                'rx_bytes': 0,
                'tx_bytes': 0,
                'rx_packets': 0,
                'tx_packets': 0,
                'configurable': iface in [PORT_1_INTERFACE, PORT_2_INTERFACE, BRIDGE_INTERFACE]
            }

            for addr in addrs:
                if addr.family == socket.AF_INET:
                    info['addresses'].append({
                        'type': 'ipv4',
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                elif addr.family == socket.AF_INET6:
                    info['addresses'].append({
                        'type': 'ipv6',
                        'address': addr.address
                    })

            if iface in net_if_stats:
                stats = net_if_stats[iface]
                info['is_up'] = stats.isup
                info['speed'] = stats.speed
                info['mtu'] = stats.mtu

            if iface in net_io:
                io = net_io[iface]
                info['rx_bytes'] = io.bytes_recv
                info['tx_bytes'] = io.bytes_sent
                info['rx_packets'] = io.packets_recv
                info['tx_packets'] = io.packets_sent

            interfaces.append(info)

        return jsonify(interfaces)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/metrics')
@login_required
def get_network_metrics():
    """Get real-time network metrics"""
    try:
        net_io = psutil.net_io_counters()
        current_time = time.time()

        metrics = {
            'timestamp': current_time,
            'rx_bytes': net_io.bytes_recv,
            'tx_bytes': net_io.bytes_sent,
            'rx_packets': net_io.packets_recv,
            'tx_packets': net_io.packets_sent,
            'rx_errors': net_io.errin,
            'tx_errors': net_io.errout,
            'rx_dropped': net_io.dropin,
            'tx_dropped': net_io.dropout
        }

        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== WARHAMMER NETWORK API ====================

@app.route('/api/warhammer/status')
@login_required
def get_warhammer_status():
    """Get WARHAMMER network daemon status"""
    try:
        result = subprocess.run(['netbird', 'status', '--json'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            status = json.loads(result.stdout)
            return jsonify(status)
        else:
            return jsonify({'error': 'WARHAMMER network not running', 'details': result.stderr}), 503
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Status check timeout'}), 504
    except FileNotFoundError:
        return jsonify({'error': 'WARHAMMER network not installed'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/peers')
@login_required
def get_warhammer_peers():
    """Get WARHAMMER network peers from management API"""
    try:
        if not WARHAMMER_TOKEN:
            return jsonify({'error': 'WARHAMMER token not configured'}), 400

        response = requests.get(
            f'https://{WARHAMMER_DOMAIN}/api/peers',
            headers=get_api_headers(),
            timeout=10
        )

        if response.status_code == 200:
            peers = response.json()
            # Enrich peers with latency data from cache
            for peer in peers:
                peer_ip = peer.get('ip', '')
                if peer_ip in peer_latency_cache:
                    peer['latency'] = peer_latency_cache[peer_ip]
                if peer_ip in latency_history:
                    peer['latency_history'] = latency_history[peer_ip]
            return jsonify(peers)
        else:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/routes')
@login_required
def get_warhammer_routes():
    """Get WARHAMMER network routes from management API"""
    try:
        if not WARHAMMER_TOKEN:
            return jsonify({'error': 'WARHAMMER token not configured'}), 400

        response = requests.get(
            f'https://{WARHAMMER_DOMAIN}/api/routes',
            headers=get_api_headers(),
            timeout=10
        )

        if response.status_code == 200:
            routes = response.json()
            # Add persistent flag to routes
            for route in routes:
                route['persistent'] = is_persistent_route(route)
            return jsonify(routes)
        else:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/routes', methods=['POST'])
@login_required
def create_warhammer_route():
    """Create a new WARHAMMER network route"""
    try:
        if not WARHAMMER_TOKEN:
            return jsonify({'error': 'WARHAMMER token not configured'}), 400

        data = request.json

        response = requests.post(
            f'https://{WARHAMMER_DOMAIN}/api/routes',
            headers=get_api_headers(),
            json=data,
            timeout=10
        )

        if response.status_code in [200, 201]:
            return jsonify(response.json())
        else:
            return jsonify({'error': f'API error: {response.status_code}', 'details': response.text}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/routes/<route_id>', methods=['PUT'])
@login_required
def update_warhammer_route(route_id):
    """Update a WARHAMMER network route (enable/disable)"""
    try:
        if not WARHAMMER_TOKEN:
            return jsonify({'error': 'WARHAMMER token not configured'}), 400

        # First get the route to check if it's persistent
        get_response = requests.get(
            f'https://{WARHAMMER_DOMAIN}/api/routes/{route_id}',
            headers=get_api_headers(),
            timeout=10
        )

        if get_response.status_code == 200:
            existing_route = get_response.json()
            if is_persistent_route(existing_route):
                return jsonify({'error': 'Cannot modify persistent route'}), 403

        data = request.json

        response = requests.put(
            f'https://{WARHAMMER_DOMAIN}/api/routes/{route_id}',
            headers=get_api_headers(),
            json=data,
            timeout=10
        )

        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/routes/<route_id>', methods=['DELETE'])
@login_required
def delete_warhammer_route(route_id):
    """Delete a WARHAMMER network route"""
    try:
        if not WARHAMMER_TOKEN:
            return jsonify({'error': 'WARHAMMER token not configured'}), 400

        # First get the route to check if it's persistent
        get_response = requests.get(
            f'https://{WARHAMMER_DOMAIN}/api/routes/{route_id}',
            headers=get_api_headers(),
            timeout=10
        )

        if get_response.status_code == 200:
            existing_route = get_response.json()
            if is_persistent_route(existing_route):
                return jsonify({'error': 'Cannot delete persistent route'}), 403

        response = requests.delete(
            f'https://{WARHAMMER_DOMAIN}/api/routes/{route_id}',
            headers=get_api_headers(),
            timeout=10
        )

        if response.status_code in [200, 204]:
            return jsonify({'message': 'Route deleted'})
        else:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/groups')
@login_required
def get_warhammer_groups():
    """Get WARHAMMER network groups from management API"""
    try:
        if not WARHAMMER_TOKEN:
            return jsonify({'error': 'WARHAMMER token not configured'}), 400

        response = requests.get(
            f'https://{WARHAMMER_DOMAIN}/api/groups',
            headers=get_api_headers(),
            timeout=10
        )

        if response.status_code == 200:
            groups = response.json()
            return jsonify(groups)
        else:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== PING & LATENCY ====================

@app.route('/api/ping/<target>')
@login_required
def ping_target(target):
    """Ping a target and return latency"""
    try:
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '2', target],
            capture_output=True, text=True, timeout=15
        )

        if result.returncode == 0:
            # Parse average latency from ping output
            lines = result.stdout.split('\n')
            for line in lines:
                if 'avg' in line or 'rtt' in line:
                    parts = line.split('=')
                    if len(parts) > 1:
                        values = parts[1].strip().split('/')
                        if len(values) >= 2:
                            latency = float(values[1])
                            # Update cache
                            peer_latency_cache[target] = latency
                            # Update history
                            if target not in latency_history:
                                latency_history[target] = []
                            latency_history[target].append(latency)
                            if len(latency_history[target]) > MAX_LATENCY_HISTORY:
                                latency_history[target].pop(0)

                            return jsonify({
                                'target': target,
                                'latency': latency,
                                'packet_loss': 0,
                                'status': 'online'
                            })
            return jsonify({'target': target, 'latency': 0, 'status': 'online'})
        else:
            return jsonify({'target': target, 'status': 'offline', 'packet_loss': 100})
    except subprocess.TimeoutExpired:
        return jsonify({'target': target, 'status': 'timeout', 'packet_loss': 100})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/latency/history')
@login_required
def get_latency_history():
    """Get latency history for all peers"""
    return jsonify(latency_history)

# ==================== SBC CONTROLS ====================

@app.route('/api/sbc/power', methods=['POST'])
@login_required
def sbc_power_control():
    """Control SBC power (reboot/shutdown)"""
    try:
        action = request.json.get('action')

        if action == 'reboot':
            subprocess.Popen(['sudo', 'reboot'])
            return jsonify({'status': 'rebooting'})
        elif action == 'shutdown':
            subprocess.Popen(['sudo', 'shutdown', '-h', 'now'])
            return jsonify({'status': 'shutting down'})
        else:
            return jsonify({'error': 'Invalid action'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sbc/services')
@login_required
def get_sbc_services():
    """Get status of important system services"""
    services = ['wg-quick@wg0', 'NetworkManager', 'ssh', 'docker']
    # Map internal service names to display names
    display_names = {
        'wg-quick@wg0': 'WARHAMMER VPN',
        'NetworkManager': 'Network Manager',
        'ssh': 'SSH Server',
        'docker': 'Docker'
    }

    results = []

    for service in services:
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()
            # Try netbird if wg-quick not found
            if service == 'wg-quick@wg0' and status != 'active':
                result2 = subprocess.run(
                    ['systemctl', 'is-active', 'netbird'],
                    capture_output=True, text=True, timeout=5
                )
                if result2.stdout.strip() == 'active':
                    status = 'active'

            results.append({
                'name': display_names.get(service, service),
                'service': service,
                'status': status,
                'active': status == 'active'
            })
        except:
            results.append({
                'name': display_names.get(service, service),
                'service': service,
                'status': 'unknown',
                'active': False
            })

    return jsonify(results)

@app.route('/api/sbc/service/<service>/<action>', methods=['POST'])
@login_required
def control_service(service, action):
    """Start/stop/restart a service"""
    allowed_services = ['netbird', 'NetworkManager', 'docker', 'wg-quick@wg0']
    allowed_actions = ['start', 'stop', 'restart']

    if service not in allowed_services:
        return jsonify({'error': 'Service not allowed'}), 403
    if action not in allowed_actions:
        return jsonify({'error': 'Action not allowed'}), 403

    try:
        result = subprocess.run(
            ['sudo', 'systemctl', action, service],
            capture_output=True, text=True, timeout=30
        )
        return jsonify({
            'service': service,
            'action': action,
            'success': result.returncode == 0,
            'message': result.stderr if result.returncode != 0 else 'OK'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== INTERFACE CONFIGURATION ====================

@app.route('/api/interface/<iface>/ip', methods=['POST'])
@login_required
def add_interface_ip(iface):
    """Add an IP address to an interface"""
    try:
        if iface not in [PORT_1_INTERFACE, PORT_2_INTERFACE, BRIDGE_INTERFACE]:
            return jsonify({'error': 'Interface not configurable'}), 403

        new_ip = request.json.get('ip')

        # Validate IP address
        try:
            ipaddress.ip_address(new_ip)
        except ValueError:
            return jsonify({'error': 'Invalid IP address'}), 400

        # Add IP using ip command
        cmd = f'sudo ip addr add {new_ip}/24 dev {iface}'
        result = subprocess.run(cmd.split(), capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({'message': 'IP address added successfully'})
        else:
            return jsonify({'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/interface/<iface>/ip', methods=['DELETE'])
@login_required
def remove_interface_ip(iface):
    """Remove an IP address from an interface"""
    try:
        if iface not in [PORT_1_INTERFACE, PORT_2_INTERFACE, BRIDGE_INTERFACE]:
            return jsonify({'error': 'Interface not configurable'}), 403

        ip_to_remove = request.json.get('ip')

        # Don't allow removing management IPs
        if ip_to_remove in [MANAGEMENT_INTERFACE_1, MANAGEMENT_INTERFACE_2, MANAGEMENT_INTERFACE_3]:
            return jsonify({'error': 'Cannot remove management IP'}), 403

        cmd = f'sudo ip addr del {ip_to_remove}/24 dev {iface}'
        result = subprocess.run(cmd.split(), capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({'message': 'IP address removed successfully'})
        else:
            return jsonify({'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== WEBSOCKET HANDLERS ====================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if 'logged_in' not in session:
        return False
    emit('connected', {'status': 'connected', 'hostname': WARHAMMER_NAME})

@socketio.on('request_metrics')
def handle_metrics_request():
    """Send current metrics to client"""
    try:
        net_io = psutil.net_io_counters()
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()

        emit('metrics_update', {
            'timestamp': time.time() * 1000,
            'cpu': cpu,
            'memory': memory.percent,
            'rx_bytes': net_io.bytes_recv,
            'tx_bytes': net_io.bytes_sent
        })
    except Exception as e:
        emit('error', {'message': str(e)})

def background_metrics_thread():
    """Background thread to push metrics updates"""
    while True:
        try:
            net_io = psutil.net_io_counters()
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()

            socketio.emit('metrics_update', {
                'timestamp': time.time() * 1000,
                'cpu': cpu,
                'memory': memory.percent,
                'rx_bytes': net_io.bytes_recv,
                'tx_bytes': net_io.bytes_sent
            })
        except:
            pass
        time.sleep(2)

# Start background thread
metrics_thread = threading.Thread(target=background_metrics_thread, daemon=True)
metrics_thread.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'

    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                     WARHAMMER                              ║
    ║           Network Overlay Management System                ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Host: {WARHAMMER_NAME:<48} ║
    ║  Port: {port:<48} ║
    ║  Network: {WARHAMMER_DOMAIN:<44} ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    socketio.run(app, host='0.0.0.0', port=port, debug=debug)
