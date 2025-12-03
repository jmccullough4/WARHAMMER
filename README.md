# WARHAMMER

**Network Overlay Management System**

A stunning, military-themed web interface for managing Netbird overlay networks and controlling LattePanda Sigma SBCs.

![Version](https://img.shields.io/badge/version-2.0.0-orange)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Real-time Network Monitoring** - Live throughput charts, latency graphs, and bandwidth statistics
- **Netbird Integration** - Full peer management, routes, and groups from your Netbird network
- **System Dashboard** - CPU, memory, disk, and temperature monitoring with animated gauges
- **SBC Controls** - Manage services, reboot/shutdown controls for LattePanda Sigma
- **Network Interfaces** - View and monitor all network interfaces in real-time
- **Beautiful UI** - Military/tactical themed interface with animations and effects
- **WebSocket Updates** - Live data streaming without page refreshes
- **Map View** - Geographic visualization of peer locations (with Mapbox token)

## Screenshots

The WARHAMMER interface features:
- Animated login screen with ember particles
- Dark tactical theme with orange/red accents
- Live updating network charts
- Collapsible panel sections
- Peer latency visualization

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd WARHAMMER
   ```

2. **Configure environment:**
   ```bash
   cp env.sh.template env.sh
   # Edit env.sh with your settings
   nano env.sh
   ```

3. **Run the application:**
   ```bash
   chmod +x run.sh
   ./run.sh
   ```

4. **Access the interface:**
   Open `http://localhost:8080` in your browser

## Configuration

Edit `env.sh` with your environment settings:

```bash
export WARHAMMER_NAME=$HOSTNAME
export NETBIRD_DOMAIN=your.netbird.domain.com
export NETBIRD_TOKEN=your_api_token
export MAPBOX_TOKEN=your_mapbox_token  # Optional, for map view
```

### Network Interfaces
Configure your interface names based on your hardware:
- `PORT_1_INTERFACE` - Primary ethernet port
- `PORT_2_INTERFACE` - Secondary ethernet port
- `BRIDGE_INTERFACE` - Bridge interface name
- `WWAN_INTERFACE` - Mobile WAN interface
- `WIFI_INTERFACE` - WiFi interface

## Default Credentials

| Username | Password   |
|----------|------------|
| admin    | warhammer  |
| operator | operator123|

**Important:** Change these credentials in production!

## Architecture

```
WARHAMMER/
├── app.py              # Flask application & API routes
├── requirements.txt    # Python dependencies
├── run.sh             # Launch script
├── env.sh.template    # Environment template
├── static/
│   ├── css/
│   │   └── main.css   # Tactical themed styles
│   ├── js/
│   │   └── main.js    # Dashboard functionality
│   └── logo/
│       └── favicon.svg
└── templates/
    ├── login.html     # Authentication page
    └── main.html      # Main dashboard
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/system/info` | GET | System metrics (CPU, RAM, disk) |
| `/api/network/interfaces` | GET | Network interface details |
| `/api/network/metrics` | GET | Network I/O statistics |
| `/api/netbird/status` | GET | Netbird daemon status |
| `/api/netbird/peers` | GET | List all Netbird peers |
| `/api/netbird/routes` | GET | List network routes |
| `/api/netbird/groups` | GET | List peer groups |
| `/api/ping/<target>` | GET | Ping a target host |
| `/api/sbc/services` | GET | System service status |
| `/api/sbc/power` | POST | Reboot/shutdown control |

## WebSocket Events

The application uses Socket.IO for real-time updates:
- `metrics_update` - Periodic CPU, memory, and network stats
- `connect` / `disconnect` - Connection status

## Requirements

- Python 3.8+
- Flask 2.3+
- Flask-SocketIO
- psutil
- requests
- Netbird installed (for peer management)

## Hardware Support

Optimized for **LattePanda Sigma**:
- Intel i5 processor monitoring
- Temperature sensors
- Multiple network interfaces
- NVMe storage

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run in debug mode
DEBUG=true python3 app.py
```

## License

MIT License - See LICENSE file for details.

## Credits

- UI Design inspired by tactical/military interfaces
- Built with Flask, Socket.IO, and Chart.js
- Netbird for secure overlay networking
