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
from datetime import timedelta, datetime
from functools import wraps
from pathlib import Path
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

# Subscription/Token configuration
SUBSCRIPTION_DATA_FILE = os.environ.get('SUBSCRIPTION_DATA_FILE', '/etc/warhammer/subscription.json')
SUBSCRIPTION_ALERT_THRESHOLDS = [30, 15, 7, 3, 1]  # Days before expiry to show alerts

# ==================== CARRIER APN DATABASE ====================
# Maps carrier names/patterns to their APN settings
# Format: { 'pattern': { 'apn': '...', 'username': '...', 'password': '...' } }
CARRIER_APN_DATABASE = {
    # Verizon
    'verizon': {'apn': 'vzwinternet', 'username': '', 'password': ''},
    'vzw': {'apn': 'vzwinternet', 'username': '', 'password': ''},
    '311480': {'apn': 'vzwinternet', 'username': '', 'password': ''},  # Verizon MCC-MNC

    # AT&T
    'at&t': {'apn': 'broadband', 'username': '', 'password': ''},
    'att': {'apn': 'broadband', 'username': '', 'password': ''},
    '310410': {'apn': 'broadband', 'username': '', 'password': ''},  # AT&T MCC-MNC
    '310280': {'apn': 'broadband', 'username': '', 'password': ''},

    # T-Mobile
    't-mobile': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},
    'tmobile': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},
    '310260': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},  # T-Mobile MCC-MNC

    # Sprint (now T-Mobile)
    'sprint': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},

    # US Cellular
    'us cellular': {'apn': 'usccinternet', 'username': '', 'password': ''},
    'uscellular': {'apn': 'usccinternet', 'username': '', 'password': ''},

    # FirstNet (AT&T public safety)
    'firstnet': {'apn': 'firstnet-broadband', 'username': '', 'password': ''},

    # Google Fi
    'google fi': {'apn': 'h2g2', 'username': '', 'password': ''},
    'fi': {'apn': 'h2g2', 'username': '', 'password': ''},

    # Mint Mobile (T-Mobile MVNO)
    'mint': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},

    # Visible (Verizon MVNO)
    'visible': {'apn': 'vsblinternet', 'username': '', 'password': ''},

    # Cricket (AT&T MVNO)
    'cricket': {'apn': 'ndo', 'username': '', 'password': ''},

    # Metro (T-Mobile MVNO)
    'metro': {'apn': 'fast.metropcs.com', 'username': '', 'password': ''},
    'metropcs': {'apn': 'fast.metropcs.com', 'username': '', 'password': ''},

    # Boost (T-Mobile MVNO)
    'boost': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},

    # Consumer Cellular
    'consumer cellular': {'apn': 'att.mvno', 'username': '', 'password': ''},

    # Tracfone
    'tracfone': {'apn': 'tfdata', 'username': '', 'password': ''},

    # Simple Mobile
    'simple mobile': {'apn': 'simple', 'username': '', 'password': ''},

    # Ting
    'ting': {'apn': 'fast.t-mobile.com', 'username': '', 'password': ''},

    # International carriers
    'rogers': {'apn': 'internet.com', 'username': '', 'password': ''},
    'bell': {'apn': 'pda.bell.ca', 'username': '', 'password': ''},
    'telus': {'apn': 'sp.telus.com', 'username': '', 'password': ''},
    'vodafone': {'apn': 'web.vodafone.de', 'username': '', 'password': ''},
    'ee': {'apn': 'everywhere', 'username': '', 'password': ''},
    'three': {'apn': 'three.co.uk', 'username': '', 'password': ''},
    'o2': {'apn': 'mobile.o2.co.uk', 'username': 'o2web', 'password': 'password'},
}

def detect_carrier_apn(operator_name, mcc_mnc=None):
    """Detect APN settings based on carrier name or MCC-MNC code"""
    if not operator_name and not mcc_mnc:
        return None

    # Try MCC-MNC first (most reliable)
    if mcc_mnc:
        mcc_mnc_clean = mcc_mnc.replace(' ', '').replace('-', '')
        if mcc_mnc_clean in CARRIER_APN_DATABASE:
            return CARRIER_APN_DATABASE[mcc_mnc_clean]

    # Try operator name matching
    if operator_name:
        operator_lower = operator_name.lower().strip()

        # Direct match
        if operator_lower in CARRIER_APN_DATABASE:
            return CARRIER_APN_DATABASE[operator_lower]

        # Partial match
        for pattern, apn_info in CARRIER_APN_DATABASE.items():
            if pattern in operator_lower or operator_lower in pattern:
                return apn_info

    return None

# ==================== SUBSCRIPTION MANAGEMENT ====================

def get_default_subscription_data():
    """Return default subscription data structure"""
    return {
        'subscription': {
            'active': True,
            'tier': 'standard',
            'start_date': None,
            'expiry_date': None,
            'license_key': None
        },
        'netbird_token': {
            'expiry_date': None,
            'last_updated': None
        },
        'alerts_dismissed': []
    }

def load_subscription_data():
    """Load subscription/token data from file"""
    try:
        if Path(SUBSCRIPTION_DATA_FILE).exists():
            with open(SUBSCRIPTION_DATA_FILE, 'r') as f:
                data = json.load(f)
                # Merge with defaults to ensure all keys exist
                default = get_default_subscription_data()
                for key in default:
                    if key not in data:
                        data[key] = default[key]
                return data
    except Exception as e:
        print(f"Error loading subscription data: {e}")
    return get_default_subscription_data()

def save_subscription_data(data):
    """Save subscription/token data to file"""
    try:
        Path(SUBSCRIPTION_DATA_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(SUBSCRIPTION_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving subscription data: {e}")
        return False

def calculate_days_remaining(expiry_date_str):
    """Calculate days remaining until expiry"""
    if not expiry_date_str:
        return None
    try:
        expiry = datetime.strptime(expiry_date_str, '%Y-%m-%d')
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        delta = expiry - today
        return delta.days
    except:
        return None

def get_subscription_status():
    """Get current subscription and token status"""
    data = load_subscription_data()

    sub = data.get('subscription', {})
    token = data.get('netbird_token', {})

    sub_days = calculate_days_remaining(sub.get('expiry_date'))
    token_days = calculate_days_remaining(token.get('expiry_date'))

    # Determine overall status
    is_expired = False
    if sub_days is not None and sub_days < 0:
        is_expired = True
    if token_days is not None and token_days < 0:
        is_expired = True

    return {
        'subscription': {
            'active': sub.get('active', True) and not is_expired,
            'tier': sub.get('tier', 'standard'),
            'start_date': sub.get('start_date'),
            'expiry_date': sub.get('expiry_date'),
            'days_remaining': sub_days,
            'license_key': sub.get('license_key')
        },
        'netbird_token': {
            'expiry_date': token.get('expiry_date'),
            'days_remaining': token_days,
            'last_updated': token.get('last_updated')
        },
        'is_expired': is_expired,
        'alerts': get_subscription_alerts(sub_days, token_days, data.get('alerts_dismissed', []))
    }

def get_subscription_alerts(sub_days, token_days, dismissed):
    """Generate alerts for upcoming expirations"""
    alerts = []

    for threshold in SUBSCRIPTION_ALERT_THRESHOLDS:
        # Subscription alerts
        if sub_days is not None and sub_days <= threshold and sub_days >= 0:
            alert_id = f"sub_{threshold}"
            if alert_id not in dismissed:
                urgency = 'critical' if threshold <= 3 else 'warning' if threshold <= 7 else 'info'
                alerts.append({
                    'id': alert_id,
                    'type': 'subscription',
                    'message': f"Subscription expires in {sub_days} day{'s' if sub_days != 1 else ''}",
                    'days': sub_days,
                    'urgency': urgency
                })
                break  # Only show one subscription alert

        # Token alerts
        if token_days is not None and token_days <= threshold and token_days >= 0:
            alert_id = f"token_{threshold}"
            if alert_id not in dismissed:
                urgency = 'critical' if threshold <= 3 else 'warning' if threshold <= 7 else 'info'
                alerts.append({
                    'id': alert_id,
                    'type': 'token',
                    'message': f"Netbird token expires in {token_days} day{'s' if token_days != 1 else ''}",
                    'days': token_days,
                    'urgency': urgency
                })
                break  # Only show one token alert

    # Expired alerts
    if sub_days is not None and sub_days < 0:
        alerts.insert(0, {
            'id': 'sub_expired',
            'type': 'subscription',
            'message': f"Subscription expired {abs(sub_days)} day{'s' if abs(sub_days) != 1 else ''} ago",
            'days': sub_days,
            'urgency': 'expired'
        })

    if token_days is not None and token_days < 0:
        alerts.insert(0, {
            'id': 'token_expired',
            'type': 'token',
            'message': f"Netbird token expired {abs(token_days)} day{'s' if abs(token_days) != 1 else ''} ago",
            'days': token_days,
            'urgency': 'expired'
        })

    return alerts

def subscription_required(f):
    """Decorator to check if subscription is active"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        status = get_subscription_status()
        if status['is_expired']:
            return jsonify({
                'error': 'Subscription expired',
                'message': 'Your WARHAMMER subscription has expired. Please renew to continue using network features.',
                'subscription_status': status
            }), 402  # Payment Required
        return f(*args, **kwargs)
    return decorated_function

# Interfaces to hide from the UI
HIDDEN_INTERFACES = ['lo', 'virbr0', 'virbr0-nic', 'docker0']

# Application version - reads from git or defaults
def get_app_version():
    """Get application version from git tag or fallback to default"""
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        # Try to get version from git describe
        result = subprocess.run(
            ['git', 'describe', '--tags', '--always'],
            cwd=app_dir,
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            tag = result.stdout.strip()
            # If it's a proper version tag, use it
            if tag.startswith('v') or tag.startswith('3.'):
                return tag
            # Otherwise it's a commit hash
            return f"3.1.0-{tag}"

        # Fallback: get short commit hash
        result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=app_dir,
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return f"3.1.0-{result.stdout.strip()}"
    except:
        pass
    return "3.1.0"

APP_VERSION = get_app_version()

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

# GPS cache for local node location
gps_cache = {
    'latitude': None,
    'longitude': None,
    'altitude': None,
    'speed': None,
    'heading': None,
    'fix_type': 0,
    'satellites': 0,
    'timestamp': None,
    'error': None
}

# Peer GPS cache - stores GPS data received from other WARHAMMER peers
peer_gps_cache = {}  # {peer_ip: {'latitude': x, 'longitude': y, 'timestamp': t, 'hostname': name}}
PEER_GPS_TIMEOUT = 300  # 5 minutes - GPS data older than this is considered stale

def get_gpsd_data():
    """Fetch GPS data from gpsd daemon"""
    global gps_cache
    try:
        import socket
        gpsd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gpsd_socket.settimeout(2)
        gpsd_socket.connect(('localhost', 2947))

        # Send watch command to start receiving data
        gpsd_socket.send(b'?WATCH={"enable":true,"json":true}\n')

        # Read responses until we get a TPV (position) report
        buffer = ""
        attempts = 0
        max_attempts = 10

        while attempts < max_attempts:
            data = gpsd_socket.recv(4096).decode('utf-8')
            buffer += data

            # Process each complete JSON object
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line.strip():
                    try:
                        msg = json.loads(line)

                        # TPV = Time-Position-Velocity report
                        if msg.get('class') == 'TPV':
                            gps_cache['latitude'] = msg.get('lat')
                            gps_cache['longitude'] = msg.get('lon')
                            gps_cache['altitude'] = msg.get('alt')
                            gps_cache['speed'] = msg.get('speed')
                            gps_cache['heading'] = msg.get('track')
                            gps_cache['fix_type'] = msg.get('mode', 0)
                            gps_cache['timestamp'] = time.time()
                            gps_cache['error'] = None

                            if gps_cache['latitude'] and gps_cache['longitude']:
                                gpsd_socket.close()
                                return gps_cache

                        # SKY = Satellite info
                        elif msg.get('class') == 'SKY':
                            satellites = msg.get('satellites', [])
                            gps_cache['satellites'] = len([s for s in satellites if s.get('used')])

                    except json.JSONDecodeError:
                        pass

            attempts += 1

        gpsd_socket.close()

    except Exception as e:
        gps_cache['error'] = str(e)

    return gps_cache

# Start background GPS polling thread
def gps_polling_thread():
    """Background thread to poll GPS data"""
    while True:
        try:
            get_gpsd_data()
        except:
            pass
        time.sleep(5)  # Poll every 5 seconds

gps_thread = threading.Thread(target=gps_polling_thread, daemon=True)
gps_thread.start()

# Start background token sync scheduler (runs at midnight UTC daily)
def token_sync_scheduler():
    """Background thread to sync token expiry daily at midnight UTC"""
    from datetime import timezone

    # Initial sync on startup (after a short delay)
    time.sleep(10)
    print("[TOKEN SYNC] Running initial token expiry sync...")
    sync_token_expiry()

    while True:
        try:
            # Calculate seconds until next midnight UTC
            now_utc = datetime.now(timezone.utc)
            tomorrow_utc = now_utc.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            seconds_until_midnight = (tomorrow_utc - now_utc).total_seconds()

            print(f"[TOKEN SYNC] Next sync scheduled in {seconds_until_midnight:.0f} seconds (midnight UTC)")
            time.sleep(seconds_until_midnight)

            # Run the sync
            print("[TOKEN SYNC] Running scheduled token expiry sync...")
            result = sync_token_expiry()
            if result.get('success'):
                print(f"[TOKEN SYNC] Sync successful: {result['token_info'].get('name')} expires {result['token_info'].get('expiration_date')}")
            else:
                print(f"[TOKEN SYNC] Sync failed: {result.get('error')}")

        except Exception as e:
            print(f"[TOKEN SYNC] Scheduler error: {e}")
            time.sleep(3600)  # Wait an hour before retrying on error

token_sync_thread = threading.Thread(target=token_sync_scheduler, daemon=True)
token_sync_thread.start()

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

            # Trigger token sync in background on login
            threading.Thread(target=sync_token_expiry, daemon=True).start()

            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Access denied.'

    return render_template('login.html', error=error, version=APP_VERSION)

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
        management_ip=MANAGEMENT_INTERFACE_1,
        version=APP_VERSION
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

@app.route('/api/system/cellular')
@login_required
def get_cellular_status():
    """Get cellular/modem signal status using ModemManager"""
    try:
        result = {
            'available': False,
            'connected': False,
            'signal_quality': 0,
            'signal_bars': 0,
            'access_technology': None,
            'operator': None,
            'state': None,
            'rssi': None,
            'imei': None,
            'iccid': None,
            'phone_number': None,
            'suggested_apn': None
        }

        # Check if ModemManager is available and get modem list
        try:
            modem_list = subprocess.run(
                ['mmcli', '-L'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if modem_list.returncode != 0 or 'No modems' in modem_list.stdout:
                return jsonify(result)

            # Extract modem number from output (e.g., "/org/freedesktop/ModemManager1/Modem/0")
            import re
            modem_match = re.search(r'/Modem/(\d+)', modem_list.stdout)
            if not modem_match:
                return jsonify(result)

            modem_num = modem_match.group(1)
            result['available'] = True

            # Get modem status
            modem_info = subprocess.run(
                ['mmcli', '-m', modem_num],
                capture_output=True,
                text=True,
                timeout=5
            )

            if modem_info.returncode == 0:
                output = modem_info.stdout

                # Parse signal quality
                signal_match = re.search(r'signal quality:\s*(\d+)', output, re.IGNORECASE)
                if signal_match:
                    signal = int(signal_match.group(1))
                    result['signal_quality'] = signal
                    # Convert to bars (0-4)
                    if signal >= 80:
                        result['signal_bars'] = 4
                    elif signal >= 60:
                        result['signal_bars'] = 3
                    elif signal >= 40:
                        result['signal_bars'] = 2
                    elif signal >= 20:
                        result['signal_bars'] = 1
                    else:
                        result['signal_bars'] = 0

                # Parse state/connection
                state_match = re.search(r'^\s*state:\s*[\'"]?(\w+)[\'"]?', output, re.MULTILINE | re.IGNORECASE)
                if state_match:
                    state = state_match.group(1).lower()
                    result['state'] = state
                    result['connected'] = state in ['connected', 'registered']

                # Parse access technology (LTE, 5G, 3G, etc.)
                tech_match = re.search(r'access tech:\s*[\'"]?(\w+)[\'"]?', output, re.IGNORECASE)
                if tech_match:
                    result['access_technology'] = tech_match.group(1).upper()

                # Parse operator name
                operator_match = re.search(r'operator name:\s*[\'"]?([^\'"\n]+)[\'"]?', output, re.IGNORECASE)
                if operator_match:
                    result['operator'] = operator_match.group(1).strip()

                # Parse IMEI (equipment id)
                imei_match = re.search(r'equipment id:\s*[\'"]?(\d+)[\'"]?', output, re.IGNORECASE)
                if imei_match:
                    result['imei'] = imei_match.group(1)

                # Parse phone number (own numbers)
                phone_match = re.search(r'own[^:]*:\s*[\'"]?(\+?[\d\s-]+)[\'"]?', output, re.IGNORECASE)
                if phone_match:
                    result['phone_number'] = phone_match.group(1).strip()

            # Get SIM info for ICCID
            try:
                # First get the SIM path
                sim_path_match = re.search(r'primary sim path:\s*(/[^\s]+)', modem_info.stdout if modem_info.returncode == 0 else '', re.IGNORECASE)
                if sim_path_match:
                    sim_path = sim_path_match.group(1)
                    sim_num_match = re.search(r'/SIM/(\d+)', sim_path)
                    if sim_num_match:
                        sim_info = subprocess.run(
                            ['mmcli', '-i', sim_num_match.group(1)],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if sim_info.returncode == 0:
                            iccid_match = re.search(r'iccid:\s*[\'"]?(\d+)[\'"]?', sim_info.stdout, re.IGNORECASE)
                            if iccid_match:
                                result['iccid'] = iccid_match.group(1)
            except:
                pass

            # Try to get more detailed signal info
            try:
                signal_info = subprocess.run(
                    ['mmcli', '-m', modem_num, '--signal-get'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if signal_info.returncode == 0:
                    output = signal_info.stdout
                    # Parse RSSI
                    rssi_match = re.search(r'rssi:\s*([-\d.]+)', output, re.IGNORECASE)
                    if rssi_match:
                        result['rssi'] = float(rssi_match.group(1))
            except:
                pass

        except FileNotFoundError:
            # mmcli not installed
            pass
        except subprocess.TimeoutExpired:
            pass

        # Detect suggested APN based on carrier
        if result['operator']:
            suggested = detect_carrier_apn(result['operator'])
            if suggested:
                result['suggested_apn'] = suggested

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'available': False}), 500

@app.route('/api/system/cellular/apn/auto-configure', methods=['POST'])
@login_required
def auto_configure_cellular():
    """Automatically detect carrier and configure APN"""
    try:
        # First get cellular status to detect carrier
        modem_list = subprocess.run(
            ['mmcli', '-L'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if modem_list.returncode != 0 or 'No modems' in modem_list.stdout:
            return jsonify({'error': 'No modem detected'}), 400

        import re
        modem_match = re.search(r'/Modem/(\d+)', modem_list.stdout)
        if not modem_match:
            return jsonify({'error': 'Could not identify modem'}), 400

        modem_num = modem_match.group(1)

        # Get modem info
        modem_info = subprocess.run(
            ['mmcli', '-m', modem_num],
            capture_output=True,
            text=True,
            timeout=5
        )

        operator = None
        if modem_info.returncode == 0:
            operator_match = re.search(r'operator name:\s*[\'"]?([^\'"\n]+)[\'"]?', modem_info.stdout, re.IGNORECASE)
            if operator_match:
                operator = operator_match.group(1).strip()

        if not operator:
            return jsonify({'error': 'Could not detect carrier. Please configure manually.'}), 400

        # Detect APN
        apn_info = detect_carrier_apn(operator)
        if not apn_info:
            return jsonify({
                'error': f'Unknown carrier: {operator}. Please configure APN manually.',
                'detected_carrier': operator
            }), 400

        # Create/update the connection
        connection_name = 'WARHAMMER-Mobile'

        # Check if connection exists
        check_conn = subprocess.run(
            ['nmcli', 'connection', 'show', connection_name],
            capture_output=True,
            text=True
        )

        if check_conn.returncode == 0:
            # Update existing
            cmd = ['nmcli', 'connection', 'modify', connection_name,
                   'gsm.apn', apn_info['apn'],
                   'connection.autoconnect', 'yes']
            if apn_info.get('username'):
                cmd.extend(['gsm.username', apn_info['username']])
            if apn_info.get('password'):
                cmd.extend(['gsm.password', apn_info['password']])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            action = 'updated'
        else:
            # Create new
            cmd = ['nmcli', 'connection', 'add',
                   'type', 'gsm',
                   'ifname', '*',
                   'con-name', connection_name,
                   'gsm.apn', apn_info['apn'],
                   'connection.autoconnect', 'yes']
            if apn_info.get('username'):
                cmd.extend(['gsm.username', apn_info['username']])
            if apn_info.get('password'):
                cmd.extend(['gsm.password', apn_info['password']])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            action = 'created'

        if result.returncode != 0:
            return jsonify({'error': f'Failed to configure: {result.stderr}'}), 500

        # Activate the connection
        activate = subprocess.run(
            ['nmcli', 'connection', 'up', connection_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        return jsonify({
            'success': True,
            'carrier': operator,
            'apn': apn_info['apn'],
            'action': action,
            'activated': activate.returncode == 0,
            'message': f'Detected {operator}, configured APN: {apn_info["apn"]}'
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Operation timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/cellular/apn')
@login_required
def get_cellular_apn():
    """Get current APN/cellular connection settings"""
    try:
        result = {
            'connections': [],
            'active_connection': None
        }

        # Get cellular connections from NetworkManager
        try:
            # List all GSM/cellular connections
            nm_connections = subprocess.run(
                ['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if nm_connections.returncode == 0:
                for line in nm_connections.stdout.strip().split('\n'):
                    if not line:
                        continue
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[1] in ['gsm', 'cdma']:
                        conn_name = parts[0]
                        device = parts[2] if len(parts) > 2 else ''

                        # Get detailed connection info
                        conn_detail = subprocess.run(
                            ['nmcli', '-t', '-f', 'gsm.apn,gsm.username,gsm.password,connection.autoconnect',
                             'connection', 'show', conn_name],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )

                        conn_info = {
                            'name': conn_name,
                            'apn': '',
                            'username': '',
                            'password': '',
                            'autoconnect': True,
                            'active': bool(device)
                        }

                        if conn_detail.returncode == 0:
                            for detail_line in conn_detail.stdout.strip().split('\n'):
                                if ':' in detail_line:
                                    key, value = detail_line.split(':', 1)
                                    if key == 'gsm.apn':
                                        conn_info['apn'] = value
                                    elif key == 'gsm.username':
                                        conn_info['username'] = value
                                    elif key == 'gsm.password':
                                        conn_info['password'] = value if value != '--' else ''
                                    elif key == 'connection.autoconnect':
                                        conn_info['autoconnect'] = value.lower() == 'yes'

                        result['connections'].append(conn_info)
                        if conn_info['active']:
                            result['active_connection'] = conn_name

        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/cellular/apn', methods=['POST'])
@login_required
def set_cellular_apn():
    """Create or update cellular APN settings"""
    try:
        data = request.json
        apn = data.get('apn', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        connection_name = data.get('connection_name', 'WARHAMMER-Mobile').strip()
        autoconnect = data.get('autoconnect', True)

        if not apn:
            return jsonify({'error': 'APN is required'}), 400

        # Check if connection already exists
        check_conn = subprocess.run(
            ['nmcli', 'connection', 'show', connection_name],
            capture_output=True,
            text=True
        )

        if check_conn.returncode == 0:
            # Update existing connection
            cmd = ['nmcli', 'connection', 'modify', connection_name,
                   'gsm.apn', apn,
                   'connection.autoconnect', 'yes' if autoconnect else 'no']

            if username:
                cmd.extend(['gsm.username', username])
            if password:
                cmd.extend(['gsm.password', password])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return jsonify({'error': f'Failed to update connection: {result.stderr}'}), 500

            action = 'updated'
        else:
            # Create new connection
            cmd = ['nmcli', 'connection', 'add',
                   'type', 'gsm',
                   'ifname', '*',
                   'con-name', connection_name,
                   'gsm.apn', apn,
                   'connection.autoconnect', 'yes' if autoconnect else 'no']

            if username:
                cmd.extend(['gsm.username', username])
            if password:
                cmd.extend(['gsm.password', password])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return jsonify({'error': f'Failed to create connection: {result.stderr}'}), 500

            action = 'created'

        # Activate the connection
        activate = subprocess.run(
            ['nmcli', 'connection', 'up', connection_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        return jsonify({
            'success': True,
            'action': action,
            'connection_name': connection_name,
            'activated': activate.returncode == 0,
            'message': f'APN configuration {action} successfully' +
                      (' and activated' if activate.returncode == 0 else ' (activation pending)')
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Operation timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/cellular/apn/<connection_name>', methods=['DELETE'])
@login_required
def delete_cellular_apn(connection_name):
    """Delete a cellular connection"""
    try:
        result = subprocess.run(
            ['nmcli', 'connection', 'delete', connection_name],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return jsonify({'error': f'Failed to delete connection: {result.stderr}'}), 500

        return jsonify({'success': True, 'message': f'Connection {connection_name} deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/cellular/connect', methods=['POST'])
@login_required
def connect_cellular():
    """Activate a cellular connection"""
    try:
        data = request.json
        connection_name = data.get('connection_name')

        if not connection_name:
            return jsonify({'error': 'Connection name required'}), 400

        result = subprocess.run(
            ['nmcli', 'connection', 'up', connection_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return jsonify({'error': f'Failed to connect: {result.stderr}'}), 500

        return jsonify({'success': True, 'message': f'Connected to {connection_name}'})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Connection timed out'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/cellular/disconnect', methods=['POST'])
@login_required
def disconnect_cellular():
    """Deactivate a cellular connection"""
    try:
        data = request.json
        connection_name = data.get('connection_name')

        if not connection_name:
            return jsonify({'error': 'Connection name required'}), 400

        result = subprocess.run(
            ['nmcli', 'connection', 'down', connection_name],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return jsonify({'error': f'Failed to disconnect: {result.stderr}'}), 500

        return jsonify({'success': True, 'message': f'Disconnected from {connection_name}'})
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
    """Get WARHAMMER network daemon status with GPS location"""
    try:
        result = subprocess.run(['netbird', 'status', '--json'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            status = json.loads(result.stdout)

            # Add GPS location data from gpsd
            if gps_cache.get('latitude') and gps_cache.get('longitude'):
                status['gps'] = {
                    'latitude': gps_cache['latitude'],
                    'longitude': gps_cache['longitude'],
                    'altitude': gps_cache.get('altitude'),
                    'speed': gps_cache.get('speed'),
                    'heading': gps_cache.get('heading'),
                    'fix_type': gps_cache.get('fix_type', 0),
                    'satellites': gps_cache.get('satellites', 0),
                    'timestamp': gps_cache.get('timestamp')
                }
            else:
                status['gps'] = None

            return jsonify(status)
        else:
            return jsonify({'error': 'WARHAMMER network not running', 'details': result.stderr}), 503
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Status check timeout'}), 504
    except FileNotFoundError:
        return jsonify({'error': 'WARHAMMER network not installed'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/gps')
@login_required
def get_gps_location():
    """Get current GPS location from gpsd"""
    return jsonify(gps_cache)

# ==================== PEER GPS SHARING ====================

@app.route('/api/peer/gps')
def get_peer_gps():
    """Public endpoint for other WARHAMMER peers to fetch this node's GPS location.
    No authentication required so peers can discover each other's locations."""
    if gps_cache.get('latitude') and gps_cache.get('longitude'):
        return jsonify({
            'hostname': WARHAMMER_NAME,
            'latitude': gps_cache['latitude'],
            'longitude': gps_cache['longitude'],
            'altitude': gps_cache.get('altitude'),
            'heading': gps_cache.get('heading'),
            'speed': gps_cache.get('speed'),
            'timestamp': gps_cache.get('timestamp'),
            'fix_type': gps_cache.get('fix_type', 0)
        })
    else:
        return jsonify({'error': 'No GPS fix available'}), 404

@app.route('/api/peer/gps/registry')
@login_required
def get_peer_gps_registry():
    """Get all known peer GPS locations from cache"""
    # Clean up stale entries
    current_time = time.time()
    valid_peers = {}
    for ip, data in peer_gps_cache.items():
        if current_time - data.get('timestamp', 0) < PEER_GPS_TIMEOUT:
            valid_peers[ip] = data
    return jsonify(valid_peers)

def fetch_peer_gps(peer_ip, port=8080):
    """Fetch GPS data from a peer's WARHAMMER instance"""
    global peer_gps_cache
    try:
        response = requests.get(
            f'http://{peer_ip}:{port}/api/peer/gps',
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('latitude') and data.get('longitude'):
                peer_gps_cache[peer_ip] = {
                    'latitude': data['latitude'],
                    'longitude': data['longitude'],
                    'altitude': data.get('altitude'),
                    'heading': data.get('heading'),
                    'speed': data.get('speed'),
                    'hostname': data.get('hostname'),
                    'timestamp': time.time()
                }
                print(f"[PEER GPS] Got GPS from {peer_ip}: {data.get('hostname')} @ {data['latitude']:.4f}, {data['longitude']:.4f}")
                return peer_gps_cache[peer_ip]
        elif response.status_code == 404:
            # Peer has no GPS fix - this is normal
            pass
        else:
            print(f"[PEER GPS] {peer_ip} returned status {response.status_code}")
    except requests.exceptions.ConnectError:
        # Peer not running WARHAMMER on this port - silent fail
        pass
    except requests.exceptions.Timeout:
        print(f"[PEER GPS] Timeout connecting to {peer_ip}:{port}")
    except Exception as e:
        print(f"[PEER GPS] Error fetching from {peer_ip}: {e}")
    return None

def fetch_all_peer_gps(peers, port=8080):
    """Fetch GPS and version from all connected peers in parallel"""
    import concurrent.futures

    connected_peers = [p for p in peers if p.get('connected') and p.get('ip')]

    if connected_peers:
        print(f"[PEER DATA] Fetching GPS and version from {len(connected_peers)} connected peers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Fetch GPS data
        gps_futures = {executor.submit(fetch_peer_gps, p['ip'], port): p['ip'] for p in connected_peers}
        # Fetch version data
        version_futures = {executor.submit(fetch_peer_version, p['ip'], port): p['ip'] for p in connected_peers}
        concurrent.futures.wait(list(gps_futures.keys()) + list(version_futures.keys()), timeout=5)

    if peer_gps_cache:
        print(f"[PEER DATA] GPS cache has {len(peer_gps_cache)} peer locations")
    if peer_version_cache:
        print(f"[PEER DATA] Version cache has {len(peer_version_cache)} peer versions")

# Peer version cache
peer_version_cache = {}
PEER_VERSION_TIMEOUT = 300  # 5 minutes

def fetch_peer_version(peer_ip, port=8080):
    """Fetch version info from a peer"""
    try:
        response = requests.get(
            f'http://{peer_ip}:{port}/api/version/public',
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            peer_version_cache[peer_ip] = {
                'version': data.get('version'),
                'timestamp': time.time()
            }
            return data
    except Exception as e:
        print(f"[PEER VERSION] Error fetching from {peer_ip}: {e}")
    return None

@app.route('/api/version')
@login_required
def get_version():
    """Get application version information (requires login)"""
    return jsonify({
        'version': APP_VERSION,
        'name': 'WARHAMMER',
        'description': 'Network Overlay Management System'
    })

@app.route('/api/version/public')
def get_version_public():
    """Get application version (public, for peer-to-peer version checking)"""
    return jsonify({
        'version': APP_VERSION,
        'name': 'WARHAMMER'
    })

# ==================== SUBSCRIPTION API ====================

@app.route('/api/subscription/status')
@login_required
def api_subscription_status():
    """Get current subscription and token status"""
    return jsonify(get_subscription_status())

@app.route('/api/subscription/update', methods=['POST'])
@login_required
def api_subscription_update():
    """Update subscription or token expiry dates"""
    try:
        data = load_subscription_data()
        updates = request.json

        if 'subscription' in updates:
            sub_update = updates['subscription']
            if 'expiry_date' in sub_update:
                data['subscription']['expiry_date'] = sub_update['expiry_date']
            if 'start_date' in sub_update:
                data['subscription']['start_date'] = sub_update['start_date']
            if 'tier' in sub_update:
                data['subscription']['tier'] = sub_update['tier']
            if 'license_key' in sub_update:
                data['subscription']['license_key'] = sub_update['license_key']
            if 'active' in sub_update:
                data['subscription']['active'] = sub_update['active']

        if 'netbird_token' in updates:
            token_update = updates['netbird_token']
            if 'expiry_date' in token_update:
                data['netbird_token']['expiry_date'] = token_update['expiry_date']
                data['netbird_token']['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Clear dismissed alerts when dates change
        if 'subscription' in updates or 'netbird_token' in updates:
            data['alerts_dismissed'] = []

        if save_subscription_data(data):
            return jsonify({
                'status': 'updated',
                'subscription_status': get_subscription_status()
            })
        else:
            return jsonify({'error': 'Failed to save subscription data'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subscription/dismiss-alert', methods=['POST'])
@login_required
def api_dismiss_alert():
    """Dismiss a subscription alert"""
    try:
        alert_id = request.json.get('alert_id')
        if not alert_id:
            return jsonify({'error': 'Alert ID required'}), 400

        data = load_subscription_data()
        if alert_id not in data['alerts_dismissed']:
            data['alerts_dismissed'].append(alert_id)
            save_subscription_data(data)

        return jsonify({'status': 'dismissed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subscription/configure', methods=['POST'])
@login_required
def api_subscription_configure():
    """Initial subscription configuration (for first-time setup)"""
    try:
        config = request.json
        data = load_subscription_data()

        # Set subscription details
        if 'subscription_expiry' in config:
            data['subscription']['expiry_date'] = config['subscription_expiry']
            data['subscription']['start_date'] = config.get('subscription_start', datetime.now().strftime('%Y-%m-%d'))
            data['subscription']['active'] = True

        if 'token_expiry' in config:
            data['netbird_token']['expiry_date'] = config['token_expiry']
            data['netbird_token']['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if 'license_key' in config:
            data['subscription']['license_key'] = config['license_key']

        if 'tier' in config:
            data['subscription']['tier'] = config['tier']

        data['alerts_dismissed'] = []

        if save_subscription_data(data):
            return jsonify({
                'status': 'configured',
                'subscription_status': get_subscription_status()
            })
        else:
            return jsonify({'error': 'Failed to save configuration'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def sync_token_expiry():
    """Sync token expiry from management server API (internal function)

    Returns dict with 'success', 'token_info', or 'error' keys
    """
    if not WARHAMMER_TOKEN:
        print("[TOKEN SYNC] No management token configured")
        return {'error': 'Management token not configured'}

    if not WARHAMMER_DOMAIN:
        print("[TOKEN SYNC] No management domain configured")
        return {'error': 'Management domain not configured'}

    try:
        print(f"[TOKEN SYNC] Querying service users from {WARHAMMER_DOMAIN}...")

        # For Service Users, query the service users list directly
        users_response = requests.get(
            f'https://{WARHAMMER_DOMAIN}/api/users?service_user=true',
            headers=get_api_headers(),
            timeout=15
        )

        if users_response.status_code != 200:
            print(f"[TOKEN SYNC] Failed to query service users: HTTP {users_response.status_code}")
            return {'error': f'Failed to query service users: {users_response.status_code}'}

        users = users_response.json()
        print(f"[TOKEN SYNC] Found {len(users)} service user(s)")

        if not users:
            return {'error': 'No service users found'}

        # Iterate through service users and find tokens
        all_tokens = []
        for user in users:
            user_id = user.get('id')
            user_name = user.get('name', 'Unknown')
            if not user_id:
                continue

            print(f"[TOKEN SYNC] Fetching tokens for user: {user_name} ({user_id})")

            tokens_response = requests.get(
                f'https://{WARHAMMER_DOMAIN}/api/users/{user_id}/tokens',
                headers=get_api_headers(),
                timeout=15
            )

            if tokens_response.status_code == 200:
                tokens = tokens_response.json()
                print(f"[TOKEN SYNC] Found {len(tokens)} token(s) for {user_name}")
                for token in tokens:
                    # Log raw token data for debugging
                    print(f"[TOKEN SYNC] Raw token data: {token}")
                    token['user_id'] = user_id
                    token['user_name'] = user_name
                    all_tokens.append(token)
            else:
                print(f"[TOKEN SYNC] Failed to get tokens for {user_name}: HTTP {tokens_response.status_code}")

        if not all_tokens:
            print("[TOKEN SYNC] No tokens found for any service user")
            return {'error': 'No tokens found for any service user'}

        print(f"[TOKEN SYNC] Processing {len(all_tokens)} total token(s)...")

        # Find the token with the soonest expiration (most relevant)
        earliest_expiry = None
        token_info = None

        for token in all_tokens:
            expiry = token.get('expiration_date')
            token_name = token.get('name', 'unnamed')
            if expiry:
                try:
                    # Handle nanoseconds - Python only supports microseconds (6 digits)
                    # Truncate .123456789Z to .123456Z
                    import re
                    expiry_normalized = re.sub(r'\.(\d{6})\d+', r'.\1', expiry)
                    expiry_normalized = expiry_normalized.replace('Z', '+00:00')
                    expiry_date = datetime.fromisoformat(expiry_normalized)
                    print(f"[TOKEN SYNC] Token '{token_name}' expires: {expiry_date.strftime('%Y-%m-%d')}")
                    if earliest_expiry is None or expiry_date < earliest_expiry:
                        earliest_expiry = expiry_date
                        token_info = {
                            'name': token_name,
                            'expiration_date': expiry_date.strftime('%Y-%m-%d'),
                            'created_at': token.get('created_at'),
                            'last_used': token.get('last_used'),
                            'user_name': token.get('user_name')
                        }
                except Exception as e:
                    print(f"[TOKEN SYNC] Error parsing token '{token_name}' expiry '{expiry}': {e}")
            else:
                print(f"[TOKEN SYNC] Token '{token_name}' has no expiration_date field")

        if token_info:
            # Auto-update the stored token expiry
            data = load_subscription_data()
            data['netbird_token']['expiry_date'] = token_info['expiration_date']
            data['netbird_token']['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            data['netbird_token']['token_name'] = token_info.get('name')
            save_subscription_data(data)

            print(f"[TOKEN SYNC] SUCCESS: {token_info['name']} expires {token_info['expiration_date']}")
            return {'success': True, 'token_info': token_info}
        else:
            print("[TOKEN SYNC] No valid token expiry found in any token")
            return {'error': 'No valid token expiry found'}

    except requests.exceptions.Timeout:
        print("[TOKEN SYNC] Request timed out")
        return {'error': 'Request timeout'}
    except requests.exceptions.ConnectionError as e:
        print(f"[TOKEN SYNC] Connection error: {e}")
        return {'error': f'Connection error: {e}'}
    except Exception as e:
        print(f"[TOKEN SYNC] Unexpected error: {e}")
        return {'error': str(e)}

@app.route('/api/subscription/fetch-token-expiry')
@login_required
def api_fetch_token_expiry():
    """Fetch token expiry from WARHAMMER management server API"""
    result = sync_token_expiry()

    if result.get('success'):
        return jsonify({
            'status': 'success',
            'token': result['token_info'],
            'subscription_status': get_subscription_status()
        })
    else:
        return jsonify({'error': result.get('error', 'Unknown error')}), 400

@app.route('/api/warhammer/peers')
@login_required
@subscription_required
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

            # Fetch GPS from connected peers in background thread
            connected_peers = [p for p in peers if p.get('connected') and p.get('ip')]
            if connected_peers:
                # Spawn background thread to fetch peer GPS (non-blocking)
                threading.Thread(
                    target=fetch_all_peer_gps,
                    args=(connected_peers,),
                    daemon=True
                ).start()

            # Enrich peers with cached data
            for peer in peers:
                peer_ip = peer.get('ip', '')
                # Add latency data from cache
                if peer_ip in peer_latency_cache:
                    peer['latency'] = peer_latency_cache[peer_ip]
                if peer_ip in latency_history:
                    peer['latency_history'] = latency_history[peer_ip]
                # Add GPS data from peer GPS cache
                if peer_ip in peer_gps_cache:
                    gps_data = peer_gps_cache[peer_ip]
                    # Only include if not stale
                    if time.time() - gps_data.get('timestamp', 0) < PEER_GPS_TIMEOUT:
                        peer['gps'] = {
                            'latitude': gps_data.get('latitude'),
                            'longitude': gps_data.get('longitude'),
                            'altitude': gps_data.get('altitude'),
                            'heading': gps_data.get('heading'),
                            'speed': gps_data.get('speed'),
                            'hostname': gps_data.get('hostname')
                        }
                # Add version data from peer version cache
                if peer_ip in peer_version_cache:
                    version_data = peer_version_cache[peer_ip]
                    if time.time() - version_data.get('timestamp', 0) < PEER_VERSION_TIMEOUT:
                        peer['warhammer_version'] = version_data.get('version')
                        # Flag if peer is behind current version
                        if version_data.get('version') and version_data.get('version') != APP_VERSION:
                            peer['version_mismatch'] = True

            # Add our own version for reference
            result = {
                'peers': peers,
                'local_version': APP_VERSION
            }
            return jsonify(result)
        else:
            return jsonify({'error': f'API error: {response.status_code}'}), response.status_code
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timeout'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/warhammer/routes')
@login_required
@subscription_required
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
@subscription_required
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
@subscription_required
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
@subscription_required
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
@subscription_required
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
            subprocess.Popen(['reboot'])
            return jsonify({'status': 'rebooting'})
        elif action == 'shutdown':
            subprocess.Popen(['shutdown', '-h', 'now'])
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
            ['systemctl', action, service],
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

# ==================== DOCKER PLUGINS ====================

# Plugin configuration storage
PLUGINS_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'plugins.json')

def load_plugins_config():
    """Load plugins configuration from file"""
    if os.path.exists(PLUGINS_CONFIG_FILE):
        try:
            with open(PLUGINS_CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'plugins': []}

def save_plugins_config(config):
    """Save plugins configuration to file"""
    with open(PLUGINS_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

@app.route('/api/plugins')
@login_required
def get_plugins():
    """Get list of installed plugins with their status"""
    config = load_plugins_config()
    plugins = []

    for plugin in config.get('plugins', []):
        plugin_info = {
            'id': plugin.get('id'),
            'name': plugin.get('name'),
            'image': plugin.get('image'),
            'ports': plugin.get('ports', []),
            'env': plugin.get('env', {}),
            'status': 'unknown',
            'running': False,
            'container_id': None
        }

        # Check if container exists and is running
        try:
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f"name={plugin['id']}", '--format', '{{.Status}}'],
                capture_output=True, text=True, timeout=10
            )
            status = result.stdout.strip()
            if status:
                plugin_info['status'] = status
                plugin_info['running'] = 'Up' in status

            # Get container ID
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f"name={plugin['id']}", '--format', '{{.ID}}'],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                plugin_info['container_id'] = result.stdout.strip()
        except:
            pass

        plugins.append(plugin_info)

    return jsonify(plugins)

@app.route('/api/plugins', methods=['POST'])
@login_required
def add_plugin():
    """Add a new plugin"""
    data = request.get_json()

    if not data.get('image'):
        return jsonify({'error': 'Docker image is required'}), 400

    # Generate plugin ID from name or image
    name = data.get('name') or data['image'].split('/')[-1].split(':')[0]
    plugin_id = f"wh-plugin-{name.lower().replace(' ', '-')}"

    plugin = {
        'id': plugin_id,
        'name': name,
        'image': data['image'],
        'ports': data.get('ports', []),
        'env': data.get('env', {}),
        'volumes': data.get('volumes', []),
        'network': data.get('network', 'host'),
        'restart_policy': data.get('restart_policy', 'unless-stopped')
    }

    config = load_plugins_config()

    # Check if plugin already exists
    for existing in config['plugins']:
        if existing['id'] == plugin_id:
            return jsonify({'error': 'Plugin with this name already exists'}), 409

    config['plugins'].append(plugin)
    save_plugins_config(config)

    # Pull the image
    try:
        subprocess.run(
            ['docker', 'pull', data['image']],
            capture_output=True, text=True, timeout=300
        )
    except Exception as e:
        return jsonify({'error': f'Failed to pull image: {str(e)}'}), 500

    return jsonify({'status': 'added', 'plugin': plugin})

@app.route('/api/plugins/<plugin_id>', methods=['DELETE'])
@login_required
def remove_plugin(plugin_id):
    """Remove a plugin"""
    config = load_plugins_config()

    # Find and remove plugin
    plugin_found = False
    for i, plugin in enumerate(config['plugins']):
        if plugin['id'] == plugin_id:
            config['plugins'].pop(i)
            plugin_found = True
            break

    if not plugin_found:
        return jsonify({'error': 'Plugin not found'}), 404

    # Stop and remove container if exists
    try:
        subprocess.run(['docker', 'stop', plugin_id], capture_output=True, timeout=30)
        subprocess.run(['docker', 'rm', plugin_id], capture_output=True, timeout=30)
    except:
        pass

    save_plugins_config(config)
    return jsonify({'status': 'removed'})

@app.route('/api/plugins/<plugin_id>/start', methods=['POST'])
@login_required
def start_plugin(plugin_id):
    """Start a plugin container"""
    config = load_plugins_config()

    # Find plugin
    plugin = None
    for p in config['plugins']:
        if p['id'] == plugin_id:
            plugin = p
            break

    if not plugin:
        return jsonify({'error': 'Plugin not found'}), 404

    try:
        # Check if container exists
        result = subprocess.run(
            ['docker', 'ps', '-a', '--filter', f"name={plugin_id}", '--format', '{{.ID}}'],
            capture_output=True, text=True, timeout=10
        )

        if result.stdout.strip():
            # Container exists, just start it
            subprocess.run(['docker', 'start', plugin_id], capture_output=True, timeout=30)
        else:
            # Create and start new container
            cmd = ['docker', 'run', '-d', '--name', plugin_id]

            # Add network mode
            if plugin.get('network'):
                cmd.extend(['--network', plugin['network']])

            # Add restart policy
            if plugin.get('restart_policy'):
                cmd.extend(['--restart', plugin['restart_policy']])

            # Add port mappings
            for port in plugin.get('ports', []):
                cmd.extend(['-p', port])

            # Add environment variables
            for key, value in plugin.get('env', {}).items():
                cmd.extend(['-e', f'{key}={value}'])

            # Add volume mounts
            for volume in plugin.get('volumes', []):
                cmd.extend(['-v', volume])

            cmd.append(plugin['image'])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return jsonify({'error': result.stderr}), 500

        return jsonify({'status': 'started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/plugins/<plugin_id>/stop', methods=['POST'])
@login_required
def stop_plugin(plugin_id):
    """Stop a plugin container"""
    try:
        result = subprocess.run(
            ['docker', 'stop', plugin_id],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return jsonify({'error': result.stderr}), 500
        return jsonify({'status': 'stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/plugins/<plugin_id>/restart', methods=['POST'])
@login_required
def restart_plugin(plugin_id):
    """Restart a plugin container"""
    try:
        result = subprocess.run(
            ['docker', 'restart', plugin_id],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({'error': result.stderr}), 500
        return jsonify({'status': 'restarted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/plugins/<plugin_id>/logs')
@login_required
def get_plugin_logs(plugin_id):
    """Get logs from a plugin container"""
    lines = request.args.get('lines', '100')
    try:
        result = subprocess.run(
            ['docker', 'logs', '--tail', lines, plugin_id],
            capture_output=True, text=True, timeout=30
        )
        return jsonify({
            'logs': result.stdout + result.stderr,
            'plugin_id': plugin_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/plugins/<plugin_id>/update', methods=['POST'])
@login_required
def update_plugin(plugin_id):
    """Update a plugin to latest image version"""
    config = load_plugins_config()

    # Find plugin
    plugin = None
    for p in config['plugins']:
        if p['id'] == plugin_id:
            plugin = p
            break

    if not plugin:
        return jsonify({'error': 'Plugin not found'}), 404

    try:
        # Pull latest image
        result = subprocess.run(
            ['docker', 'pull', plugin['image']],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return jsonify({'error': f'Failed to pull image: {result.stderr}'}), 500

        # Stop and remove old container
        subprocess.run(['docker', 'stop', plugin_id], capture_output=True, timeout=30)
        subprocess.run(['docker', 'rm', plugin_id], capture_output=True, timeout=30)

        # Start will create new container with updated image
        return start_plugin(plugin_id)

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

        # Protect guarded IPs on br0 - these should never be changed via UI
        # Guarded IPs: 10.x.100.1/24 pattern and 18.18.18.18
        if iface == BRIDGE_INTERFACE:
            # Check for 18.18.18.18
            if ip_to_remove == '18.18.18.18' or ip_to_remove.startswith('18.18.18.18/'):
                return jsonify({'error': 'Cannot remove guarded IP address (18.18.18.18)'}), 403

            # Check for 10.x.100.1 pattern (e.g., 10.109.100.1, 10.0.100.1, etc.)
            import re
            if re.match(r'^10\.\d+\.100\.1(/\d+)?$', ip_to_remove):
                return jsonify({'error': 'Cannot remove guarded IP address (10.x.100.1)'}), 403

        cmd = f'sudo ip addr del {ip_to_remove}/24 dev {iface}'
        result = subprocess.run(cmd.split(), capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({'message': 'IP address removed successfully'})
        else:
            return jsonify({'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== SYSTEM UPGRADE ====================

upgrade_status = {
    'running': False,
    'progress': 0,
    'stage': '',
    'log': [],
    'error': None,
    'completed': False,
    'reboot_required': False,
    'upgrade_type': None
}

def check_reboot_required():
    """Check if system reboot is required after upgrade"""
    # Check for Ubuntu/Debian reboot-required file
    if os.path.exists('/var/run/reboot-required'):
        return True
    # Check for reboot-required.pkgs for kernel updates
    if os.path.exists('/var/run/reboot-required.pkgs'):
        try:
            with open('/var/run/reboot-required.pkgs', 'r') as f:
                pkgs = f.read()
                if 'linux-' in pkgs:
                    return True
        except:
            pass
    return False

def run_upgrade_task(upgrade_type='full'):
    """Background task to run system upgrade

    Args:
        upgrade_type: 'ui' for UI-only (fast), 'full' for full system upgrade
    """
    global upgrade_status
    upgrade_status = {
        'running': True,
        'progress': 0,
        'stage': 'Starting upgrade...',
        'log': [],
        'error': None,
        'completed': False,
        'reboot_required': False,
        'upgrade_type': upgrade_type
    }

    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))

        if upgrade_type == 'full':
            # Full system upgrade: apt update/upgrade + UI
            apt_success = True

            # Stage 1: Update package lists
            upgrade_status['stage'] = 'Updating package lists...'
            upgrade_status['progress'] = 10
            upgrade_status['log'].append('[INFO] Running apt update...')
            socketio.emit('upgrade_progress', upgrade_status)

            # Try apt update
            try:
                result = subprocess.run(
                    ['apt-get', 'update'],
                    capture_output=True, text=True, timeout=300,
                    env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
                )
                apt_output = result.stdout + result.stderr

                # Check for permission errors (real blockers)
                if 'Permission denied' in apt_output or 'Operation not permitted' in apt_output:
                    upgrade_status['log'].append('[WARN] System package updates not available in this environment')
                    upgrade_status['log'].append('[INFO] Use "apt update && apt upgrade" from terminal for system updates')
                    apt_success = False
                elif result.returncode != 0:
                    # apt update returns non-zero if ANY repo has issues, but we can still proceed
                    # Check if we got at least some successful updates (Hit or Get lines)
                    if 'Hit:' in apt_output or 'Get:' in apt_output:
                        upgrade_status['log'].append('[WARN] Some repositories had errors:')
                        # Show error lines
                        for line in apt_output.split('\n'):
                            if line.startswith('Err:') or (line.startswith('E:') and 'Release' in line):
                                upgrade_status['log'].append(f'  {line[:80]}')
                        upgrade_status['log'].append('[OK] Package lists partially updated - continuing')
                    else:
                        upgrade_status['log'].append(f'[ERROR] apt update failed: {apt_output[:300]}')
                        apt_success = False
                else:
                    upgrade_status['log'].append('[OK] Package lists updated')
            except subprocess.TimeoutExpired:
                upgrade_status['log'].append('[WARN] apt update timed out')
                apt_success = False
            except FileNotFoundError as e:
                upgrade_status['log'].append(f'[WARN] Command not found: {e}')
                apt_success = False

            # Stage 2: Upgrade packages (only if apt update succeeded)
            if apt_success:
                upgrade_status['stage'] = 'Upgrading system packages...'
                upgrade_status['progress'] = 30
                upgrade_status['log'].append('[INFO] Running apt upgrade...')
                socketio.emit('upgrade_progress', upgrade_status)

                try:
                    result = subprocess.run(
                        ['apt-get', 'upgrade', '-y'],
                        capture_output=True, text=True, timeout=1800,
                        env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
                    )
                    apt_output = result.stdout + result.stderr
                    if result.returncode != 0:
                        upgrade_status['log'].append(f'[WARN] apt upgrade had issues: {apt_output[-200:]}')
                    else:
                        # Count upgraded packages
                        upgraded = apt_output.count('Unpacking') + apt_output.count('Setting up')
                        if upgraded > 0:
                            upgrade_status['log'].append(f'[OK] System packages upgraded ({upgraded // 2} packages)')
                        else:
                            upgrade_status['log'].append('[OK] System packages are up to date')
                except subprocess.TimeoutExpired:
                    upgrade_status['log'].append('[WARN] apt upgrade timed out')

            upgrade_status['progress'] = 60
            socketio.emit('upgrade_progress', upgrade_status)

            # Stage 3: Update WARHAMMER application (git pull)
            upgrade_status['stage'] = 'Updating WARHAMMER application...'
            upgrade_status['progress'] = 70
            upgrade_status['log'].append('[INFO] Checking for WARHAMMER updates...')
            socketio.emit('upgrade_progress', upgrade_status)

            if os.path.exists(os.path.join(app_dir, '.git')):
                result = subprocess.run(
                    ['git', 'pull', '--ff-only'],
                    cwd=app_dir,
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    upgrade_status['log'].append(f'[OK] WARHAMMER updated: {result.stdout.strip()}')
                else:
                    upgrade_status['log'].append(f'[WARN] Git pull skipped: {result.stderr.strip()}')
            else:
                upgrade_status['log'].append('[INFO] Not a git repository, skipping app update')

            # Stage 4: Cleanup (only if apt was working)
            if apt_success:
                upgrade_status['stage'] = 'Cleaning up...'
                upgrade_status['progress'] = 85
                upgrade_status['log'].append('[INFO] Running apt autoremove...')
                socketio.emit('upgrade_progress', upgrade_status)

                subprocess.run(['apt-get', 'autoremove', '-y'], capture_output=True, timeout=300, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
                upgrade_status['log'].append('[OK] Cleanup completed')

                # Check if reboot is required
                upgrade_status['reboot_required'] = check_reboot_required()
                if upgrade_status['reboot_required']:
                    upgrade_status['log'].append('[INFO] System reboot recommended (kernel update detected)')
            else:
                upgrade_status['progress'] = 85

        else:
            # UI-only upgrade: just git pull
            upgrade_status['stage'] = 'Updating WARHAMMER UI...'
            upgrade_status['progress'] = 20
            upgrade_status['log'].append('[INFO] Fetching latest WARHAMMER updates...')
            socketio.emit('upgrade_progress', upgrade_status)

            if os.path.exists(os.path.join(app_dir, '.git')):
                # Fetch first
                result = subprocess.run(
                    ['git', 'fetch', 'origin'],
                    cwd=app_dir,
                    capture_output=True, text=True, timeout=120
                )
                upgrade_status['progress'] = 40
                socketio.emit('upgrade_progress', upgrade_status)

                # Pull changes
                result = subprocess.run(
                    ['git', 'pull', '--ff-only'],
                    cwd=app_dir,
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if 'Already up to date' in output:
                        upgrade_status['log'].append('[OK] WARHAMMER is already up to date')
                    else:
                        upgrade_status['log'].append(f'[OK] WARHAMMER updated: {output}')
                else:
                    upgrade_status['log'].append(f'[WARN] Git pull issue: {result.stderr.strip()}')

                upgrade_status['progress'] = 80
                socketio.emit('upgrade_progress', upgrade_status)
            else:
                upgrade_status['log'].append('[WARN] Not a git repository, no updates available')

            # UI-only never requires reboot
            upgrade_status['reboot_required'] = False

        # Done - notify client before restart
        upgrade_status['stage'] = 'Upgrade completed! Restarting service...'
        upgrade_status['progress'] = 95
        upgrade_status['log'].append('[SUCCESS] Upgrade completed')
        upgrade_status['log'].append('[INFO] Restarting WARHAMMER service...')
        socketio.emit('upgrade_progress', upgrade_status)

        # Give the client time to receive the message
        time.sleep(2)

        upgrade_status['stage'] = 'Service restarting...'
        upgrade_status['progress'] = 100
        upgrade_status['completed'] = True
        upgrade_status['running'] = False
        upgrade_status['service_restarting'] = True
        socketio.emit('upgrade_progress', upgrade_status)

        # Schedule service restart after a short delay (allows response to be sent)
        def restart_service():
            time.sleep(1)
            subprocess.run(['systemctl', 'restart', 'warhammer'], capture_output=True)

        restart_thread = threading.Thread(target=restart_service, daemon=True)
        restart_thread.start()

    except Exception as e:
        upgrade_status['error'] = str(e)
        upgrade_status['running'] = False
        upgrade_status['stage'] = 'Upgrade failed'
        upgrade_status['log'].append(f'[ERROR] {str(e)}')
        socketio.emit('upgrade_progress', upgrade_status)

@app.route('/api/system/upgrade/check')
@login_required
def check_for_updates():
    """Check for available updates without applying them"""
    try:
        updates = {
            'ui_update_available': False,
            'system_updates_available': False,
            'latest_commit': None,
            'system_packages': [],
            'current_version': APP_VERSION
        }

        app_dir = os.path.dirname(os.path.abspath(__file__))

        # Check for UI updates (git)
        if os.path.exists(os.path.join(app_dir, '.git')):
            # Fetch latest from remote
            subprocess.run(
                ['git', 'fetch', 'origin'],
                cwd=app_dir, capture_output=True, timeout=30
            )

            # Get current branch
            branch_result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=app_dir, capture_output=True, text=True, timeout=5
            )
            current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else 'main'
            updates['current_branch'] = current_branch

            # Check if there are new commits
            result = subprocess.run(
                ['git', 'rev-list', '--count', f'HEAD..origin/{current_branch}'],
                cwd=app_dir, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0 and result.stdout.strip() and int(result.stdout.strip()) > 0:
                updates['ui_update_available'] = True
                updates['commits_behind'] = int(result.stdout.strip())

                # Get the most recent commit message from remote (full message)
                commit_result = subprocess.run(
                    ['git', 'log', f'origin/{current_branch}', '-1', '--format=%H%n%s%n%b'],
                    cwd=app_dir, capture_output=True, text=True, timeout=10
                )

                if commit_result.returncode == 0:
                    lines = commit_result.stdout.strip().split('\n')
                    commit_hash = lines[0] if lines else ''
                    commit_subject = lines[1] if len(lines) > 1 else ''
                    commit_body = '\n'.join(lines[2:]).strip() if len(lines) > 2 else ''

                    updates['latest_commit'] = {
                        'hash': commit_hash[:8],
                        'subject': commit_subject,
                        'body': commit_body,
                        'full_message': commit_subject + ('\n\n' + commit_body if commit_body else '')
                    }

        # Check for system updates (apt)
        try:
            # Update package lists quietly
            subprocess.run(['apt-get', 'update', '-qq'], capture_output=True, timeout=60, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})

            # Check upgradable packages
            result = subprocess.run(
                ['apt', 'list', '--upgradable'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                lines = [l for l in result.stdout.strip().split('\n') if '/' in l]
                if lines:
                    updates['system_updates_available'] = True
                    updates['system_packages'] = [l.split('/')[0] for l in lines[:10]]  # Limit to 10
                    updates['system_package_count'] = len(lines)
        except:
            pass

        return jsonify(updates)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/upgrade', methods=['POST'])
@login_required
def start_system_upgrade():
    """Start system upgrade in background"""
    global upgrade_status

    if upgrade_status['running']:
        return jsonify({'error': 'Upgrade already in progress'}), 409

    # Get upgrade type from request
    data = request.json or {}
    upgrade_type = data.get('type', 'full')  # 'ui' or 'full'

    if upgrade_type not in ['ui', 'full']:
        return jsonify({'error': 'Invalid upgrade type'}), 400

    # Start upgrade in background thread
    upgrade_thread = threading.Thread(target=run_upgrade_task, args=(upgrade_type,), daemon=True)
    upgrade_thread.start()

    return jsonify({'status': 'started', 'message': f'{upgrade_type.upper()} upgrade started', 'type': upgrade_type})

@app.route('/api/system/upgrade/status')
@login_required
def get_upgrade_status():
    """Get current upgrade status"""
    return jsonify(upgrade_status)

@app.route('/api/system/upgrade/reset', methods=['POST'])
@login_required
def reset_upgrade_status():
    """Reset upgrade status after completion"""
    global upgrade_status
    if not upgrade_status['running']:
        upgrade_status = {
            'running': False,
            'progress': 0,
            'stage': '',
            'log': [],
            'error': None,
            'completed': False,
            'reboot_required': False,
            'upgrade_type': None
        }
    return jsonify({'status': 'reset'})

@app.route('/api/system/restart-app', methods=['POST'])
@login_required
def restart_app():
    """Restart the WARHAMMER application"""
    try:
        # Use systemctl to restart the service if running as a service
        # Otherwise just exit and let supervisor/systemd restart
        service_name = 'warhammer'
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Running as systemd service
            subprocess.Popen(['systemctl', 'restart', service_name])
            return jsonify({'status': 'restarting', 'method': 'systemd'})
        else:
            # Just exit, let the parent process restart us
            def delayed_exit():
                time.sleep(1)
                os._exit(0)
            threading.Thread(target=delayed_exit, daemon=True).start()
            return jsonify({'status': 'restarting', 'method': 'exit'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== NETWORK-WIDE UPDATES ====================

@app.route('/api/system/upgrade/peers')
@login_required
def get_outdated_peers():
    """Get list of peers that need updates"""
    outdated = []
    for peer_ip, version_data in peer_version_cache.items():
        if version_data.get('version') and version_data.get('version') != APP_VERSION:
            outdated.append({
                'ip': peer_ip,
                'version': version_data.get('version'),
                'name': version_data.get('name', 'Unknown'),
                'timestamp': version_data.get('timestamp', 0)
            })
    return jsonify({
        'local_version': APP_VERSION,
        'outdated_peers': outdated
    })

@app.route('/api/system/upgrade/peer/<peer_ip>', methods=['POST'])
@login_required
def trigger_peer_upgrade(peer_ip):
    """Trigger upgrade on a specific peer"""
    try:
        # Send upgrade request to peer
        response = requests.post(
            f'http://{peer_ip}:5000/api/system/upgrade/remote',
            timeout=10,
            json={'initiator': request.host}
        )
        if response.status_code == 200:
            return jsonify({'status': 'triggered', 'peer': peer_ip})
        else:
            return jsonify({'error': f'Peer returned {response.status_code}'}), 400
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Peer did not respond in time'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/upgrade/remote', methods=['POST'])
@login_required
def receive_remote_upgrade():
    """Receive upgrade request from another peer"""
    data = request.get_json() or {}
    initiator = data.get('initiator', 'unknown')

    # Check if we're already upgrading
    if upgrade_status.get('running'):
        return jsonify({'error': 'Upgrade already in progress'}), 409

    # Start the upgrade in background
    def do_remote_upgrade():
        global upgrade_status
        upgrade_status = {
            'running': True,
            'progress': 0,
            'stage': f'Remote upgrade initiated by {initiator}',
            'log': [f'Upgrade triggered by peer: {initiator}'],
            'error': None,
            'completed': False,
            'reboot_required': False,
            'upgrade_type': 'remote'
        }

        try:
            # Pull latest code
            upgrade_status['stage'] = 'Pulling latest code...'
            upgrade_status['progress'] = 30
            result = subprocess.run(
                ['git', 'pull'],
                cwd='/home/user/WARHAMMER',
                capture_output=True, text=True, timeout=60
            )
            upgrade_status['log'].append(result.stdout)

            if result.returncode != 0:
                upgrade_status['error'] = result.stderr
                upgrade_status['running'] = False
                return

            upgrade_status['progress'] = 80
            upgrade_status['stage'] = 'Restarting service...'
            upgrade_status['completed'] = True
            upgrade_status['service_restarting'] = True
            upgrade_status['running'] = False

            # Restart service
            def restart_service():
                time.sleep(1)
                subprocess.run(['systemctl', 'restart', 'warhammer'], capture_output=True)
            threading.Thread(target=restart_service, daemon=True).start()

        except Exception as e:
            upgrade_status['error'] = str(e)
            upgrade_status['running'] = False

    threading.Thread(target=do_remote_upgrade, daemon=True).start()
    return jsonify({'status': 'upgrade_started'})

@app.route('/api/system/upgrade/network', methods=['POST'])
@login_required
def trigger_network_upgrade():
    """Trigger upgrade on all outdated peers"""
    results = []
    for peer_ip, version_data in peer_version_cache.items():
        if version_data.get('version') and version_data.get('version') != APP_VERSION:
            try:
                response = requests.post(
                    f'http://{peer_ip}:5000/api/system/upgrade/remote',
                    timeout=10,
                    json={'initiator': request.host}
                )
                results.append({
                    'ip': peer_ip,
                    'status': 'triggered' if response.status_code == 200 else 'failed',
                    'code': response.status_code
                })
            except Exception as e:
                results.append({
                    'ip': peer_ip,
                    'status': 'error',
                    'error': str(e)
                })
    return jsonify({'results': results})

# ==================== IPERF3 SPEEDTEST ====================

iperf_status = {
    'running': False,
    'target': None,
    'results': [],
    'final': None,
    'error': None
}

def run_iperf_test(target_ip):
    """Run iperf3 test against target peer with live updates"""
    global iperf_status
    import re

    iperf_status = {
        'running': True,
        'target': target_ip,
        'results': [],
        'final': None,
        'error': None,
        'phase': 'download'  # Track download vs upload phase
    }

    try:
        # Run iperf3 with 1-second interval reports for live updates
        # Use -f m for Mbits format, -i 1 for 1-second intervals
        process = subprocess.Popen(
            ['iperf3', '-c', target_ip, '-t', '10', '-i', '1', '-f', 'm'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )

        download_total = 0
        upload_total = 0
        download_count = 0
        upload_count = 0
        in_reverse = False  # Track if we're in upload (reverse) phase

        # Read output line by line for live updates
        for line in process.stdout:
            line = line.strip()

            # Check for reverse (upload) phase indicator
            if 'Reverse mode' in line or 'receiver' in line.lower():
                in_reverse = True
                iperf_status['phase'] = 'upload'

            # Parse interval result lines (format: "[  5]   0.00-1.00   sec  XX.X MBytes  XXX Mbits/sec")
            match = re.search(r'\[\s*\d+\]\s+[\d.]+-[\d.]+\s+sec\s+([\d.]+)\s+MBytes\s+([\d.]+)\s+Mbits/sec', line)
            if match:
                mbytes = float(match.group(1))
                mbps = float(match.group(2))

                result = {
                    'seconds': len(iperf_status['results']) + 1,
                    'bytes': int(mbytes * 1024 * 1024),
                    'bits_per_second': mbps * 1000000,
                    'phase': 'upload' if in_reverse else 'download'
                }

                iperf_status['results'].append(result)

                # Track totals for final calculation
                if in_reverse:
                    upload_total += mbps
                    upload_count += 1
                else:
                    download_total += mbps
                    download_count += 1

                # Emit live update
                socketio.emit('iperf_progress', iperf_status)

            # Check for sender/receiver summary lines
            sender_match = re.search(r'sender\s*$', line)
            receiver_match = re.search(r'receiver\s*$', line)

        # Wait for completion
        process.wait(timeout=15)

        # Calculate final averages
        avg_download = (download_total / download_count) if download_count > 0 else 0
        avg_upload = (upload_total / upload_count) if upload_count > 0 else 0

        iperf_status['final'] = {
            'sent': {
                'bytes': int(upload_total * 1024 * 1024 / 8) if upload_count > 0 else 0,
                'bits_per_second': avg_upload * 1000000,
                'retransmits': 0
            },
            'received': {
                'bytes': int(download_total * 1024 * 1024 / 8) if download_count > 0 else 0,
                'bits_per_second': avg_download * 1000000
            }
        }

        iperf_status['running'] = False
        iperf_status['phase'] = 'complete'
        socketio.emit('iperf_complete', iperf_status)

    except subprocess.TimeoutExpired:
        process.kill()
        iperf_status['error'] = 'Test timed out'
        iperf_status['running'] = False
        socketio.emit('iperf_complete', iperf_status)
    except FileNotFoundError:
        iperf_status['error'] = 'iperf3 not installed on this system'
        iperf_status['running'] = False
        socketio.emit('iperf_complete', iperf_status)
    except Exception as e:
        iperf_status['error'] = str(e)
        iperf_status['running'] = False
        socketio.emit('iperf_complete', iperf_status)

@app.route('/api/iperf/<target>', methods=['POST'])
@login_required
def start_iperf_test(target):
    """Start iperf3 test against target peer"""
    global iperf_status

    if iperf_status['running']:
        return jsonify({'error': 'Test already in progress'}), 409

    # Validate target IP
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400

    # Start test in background
    iperf_thread = threading.Thread(target=run_iperf_test, args=(target,), daemon=True)
    iperf_thread.start()

    return jsonify({'status': 'started', 'target': target})

@app.route('/api/iperf/status')
@login_required
def get_iperf_status():
    """Get current iperf test status"""
    return jsonify(iperf_status)

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

    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
