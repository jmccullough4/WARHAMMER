#!/bin/bash
#
# WARHAMMER Installation Script
# Network Overlay Management System
#
# This script installs WARHAMMER as a systemd service with
# proper bridge configuration and DHCP isolation
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/warhammer"
SERVICE_NAME="warhammer"
SERVICE_USER="warhammer"
VENV_DIR="${INSTALL_DIR}/venv"
CONFIG_FILE="/etc/warhammer/config.env"
DEFAULT_PORT=8080

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                     WARHAMMER                              ║"
    echo "║           Network Overlay Management System                ║"
    echo "║                   Installation Script                      ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print status messages
info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

# Detect the source directory
detect_source() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${SCRIPT_DIR}/app.py" ]]; then
        SOURCE_DIR="${SCRIPT_DIR}"
        success "Source directory: ${SOURCE_DIR}"
    else
        error "Cannot find app.py in script directory"
    fi
}

# Install system dependencies
install_dependencies() {
    info "Installing system dependencies..."

    apt-get update -qq

    # Core dependencies
    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        iperf3 \
        gpsd \
        gpsd-clients \
        modemmanager \
        ebtables \
        iptables \
        bridge-utils \
        net-tools \
        iproute2 \
        > /dev/null 2>&1

    success "System dependencies installed"
}

# Create service user
create_user() {
    info "Creating service user..."

    if id "${SERVICE_USER}" &>/dev/null; then
        warn "User ${SERVICE_USER} already exists"
    else
        useradd --system --no-create-home --shell /bin/false "${SERVICE_USER}"
        success "Created user: ${SERVICE_USER}"
    fi

    # Add user to required groups
    usermod -aG dialout,netdev "${SERVICE_USER}" 2>/dev/null || true
}

# Install application files
install_application() {
    info "Installing application to ${INSTALL_DIR}..."

    # Create install directory
    mkdir -p "${INSTALL_DIR}"

    # Copy application files
    cp -r "${SOURCE_DIR}"/* "${INSTALL_DIR}/"

    # Remove install script from install dir (keep in source)
    rm -f "${INSTALL_DIR}/install.sh"

    # Preserve git directory for updates
    if [[ -d "${SOURCE_DIR}/.git" ]]; then
        cp -r "${SOURCE_DIR}/.git" "${INSTALL_DIR}/"
    fi

    success "Application files installed"
}

# Setup Python virtual environment
setup_venv() {
    info "Setting up Python virtual environment..."

    # Create fresh venv
    rm -rf "${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"

    # Upgrade pip and install wheel
    "${VENV_DIR}/bin/pip" install --upgrade pip wheel setuptools -q

    # Install requirements
    if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
        "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q
    else
        # Install core dependencies
        "${VENV_DIR}/bin/pip" install \
            flask \
            flask-socketio \
            python-socketio \
            requests \
            psutil \
            eventlet \
            gevent \
            gevent-websocket \
            -q
    fi

    # Verify critical imports work
    if "${VENV_DIR}/bin/python" -c "import flask; import flask_socketio; import psutil; import eventlet" 2>/dev/null; then
        success "Python environment configured and verified"
    else
        error "Python dependency verification failed"
    fi
}

# Create configuration file
create_config() {
    info "Creating configuration..."

    mkdir -p /etc/warhammer

    if [[ -f "${CONFIG_FILE}" ]]; then
        warn "Configuration file already exists, preserving..."
    else
        cat > "${CONFIG_FILE}" << 'EOF'
# WARHAMMER Configuration
# Network Overlay Management System

# Server Settings
PORT=8080
DEBUG=false
SECRET_KEY=change-this-to-a-secure-random-string

# Network Settings
WARHAMMER_NAME=
NETBIRD_DOMAIN=
NETBIRD_TOKEN=

# Mapbox (optional, for peer location map)
MAPBOX_TOKEN=

# Interface Configuration
MANAGEMENT_INTERFACE_1=
MANAGEMENT_INTERFACE_2=18.18.18.18
MANAGEMENT_INTERFACE_3=10.109.100.1
BRIDGE_INTERFACE=br0
WWAN_INTERFACE=wwan0
WIFI_INTERFACE=wlo1
PORT_1_INTERFACE=enp87s0
PORT_2_INTERFACE=enp86s0
BRIDGED_CIDR=10.109.100.1/24

# Netplan Configuration
BASE_NETPLAN=/etc/netplan/01-warhammer.yaml
EOF
        success "Configuration file created: ${CONFIG_FILE}"
        warn "Edit ${CONFIG_FILE} to configure your installation"
    fi

    # Create subscription data directory
    mkdir -p /etc/warhammer
    if [[ ! -f /etc/warhammer/subscription.json ]]; then
        echo '{}' > /etc/warhammer/subscription.json
    fi
    chmod 644 /etc/warhammer/subscription.json
}

# Setup DHCP isolation with ebtables
setup_dhcp_isolation() {
    info "Setting up DHCP isolation rules..."

    # Create the DHCP isolation script
    cat > "${INSTALL_DIR}/scripts/dhcp-isolate.sh" << 'EOFSCRIPT'
#!/bin/bash
#
# WARHAMMER DHCP Isolation Script
# Blocks upstream DHCP servers from reaching local devices
# while allowing the bridge to receive DHCP from upstream
#

# Load config
source /etc/warhammer/config.env 2>/dev/null || true

PORT_1="${PORT_1_INTERFACE:-enp87s0}"
PORT_2="${PORT_2_INTERFACE:-enp86s0}"
BRIDGE="${BRIDGE_INTERFACE:-br0}"

case "$1" in
    start)
        echo "Enabling DHCP isolation..."

        # Flush existing BROUTING rules
        ebtables -t broute -F 2>/dev/null || true

        # Block DHCP server responses (BOOTPS, port 67) from Port 1 to Port 2
        # This prevents upstream DHCP servers from issuing IPs to local devices
        # DHCP server -> client uses UDP port 67 (source) to 68 (dest)
        ebtables -t broute -A BROUTING -i ${PORT_1} -p IPv4 --ip-protocol udp \
            --ip-source-port 67 -j DROP 2>/dev/null || true

        # Also block on the bridge input for safety
        ebtables -A INPUT -i ${PORT_1} -p IPv4 --ip-protocol udp \
            --ip-source-port 67 -j DROP 2>/dev/null || true

        # Allow our DHCP client on the bridge to work by not blocking
        # DHCP responses destined to the bridge's own MAC

        echo "DHCP isolation enabled"
        ;;

    stop)
        echo "Disabling DHCP isolation..."
        ebtables -t broute -F 2>/dev/null || true
        ebtables -F 2>/dev/null || true
        echo "DHCP isolation disabled"
        ;;

    status)
        echo "=== BROUTING table ==="
        ebtables -t broute -L 2>/dev/null || echo "No brouting rules"
        echo ""
        echo "=== FILTER table ==="
        ebtables -L 2>/dev/null || echo "No filter rules"
        ;;

    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
EOFSCRIPT

    chmod +x "${INSTALL_DIR}/scripts/dhcp-isolate.sh"

    # Create systemd service for DHCP isolation
    cat > /etc/systemd/system/warhammer-dhcp-isolate.service << EOF
[Unit]
Description=WARHAMMER DHCP Isolation Service
Documentation=https://github.com/your-org/warhammer
Before=network-online.target
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${INSTALL_DIR}/scripts/dhcp-isolate.sh start
ExecStop=${INSTALL_DIR}/scripts/dhcp-isolate.sh stop

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable warhammer-dhcp-isolate.service

    success "DHCP isolation configured"
}

# Create sample netplan configuration
create_netplan_config() {
    info "Creating netplan configuration template..."

    mkdir -p "${INSTALL_DIR}/config"

    # Create a sample netplan config for bridged mode with DHCP
    # Uses NetworkManager as renderer for better cellular/modem support
    cat > "${INSTALL_DIR}/config/netplan-bridge-dhcp.yaml" << 'EOF'
# WARHAMMER Netplan Configuration
# Bridge with DHCP from upstream (Port 1) + static IPs
# Uses NetworkManager for better cellular/modem support
#
# Copy this to /etc/netplan/01-warhammer.yaml and run: sudo netplan apply
#
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    # Port 1 - WAN/Upstream (will be bridged)
    enp87s0:
      dhcp4: false
      dhcp6: false
    # Port 2 - LAN (will be bridged)
    enp86s0:
      dhcp4: false
      dhcp6: false
  bridges:
    br0:
      interfaces: [enp87s0, enp86s0]
      dhcp4: true
      dhcp4-overrides:
        route-metric: 100
        use-dns: true
        use-routes: true
      addresses:
        - 10.109.100.1/24
        - 18.18.18.18/32
      parameters:
        stp: false
        forward-delay: 0
# Note: Cellular/modem connections are managed via NetworkManager (nmcli)
# Use the WARHAMMER UI or: nmcli connection add type gsm ifname "*" con-name "Mobile" apn "YOUR_APN"
EOF

    # Create a sample netplan config for unbridged mode
    cat > "${INSTALL_DIR}/config/netplan-unbridged.yaml" << 'EOF'
# WARHAMMER Netplan Configuration
# Unbridged mode - Port 1 gets DHCP, Port 2 is static
# Uses NetworkManager for better cellular/modem support
#
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    # Port 1 - WAN/Upstream with DHCP
    enp87s0:
      dhcp4: true
      dhcp4-overrides:
        route-metric: 100
    # Port 2 - LAN static
    enp86s0:
      addresses:
        - 10.109.100.1/24
        - 18.18.18.18/32
# Note: Cellular/modem connections are managed via NetworkManager (nmcli)
# Use the WARHAMMER UI or: nmcli connection add type gsm ifname "*" con-name "Mobile" apn "YOUR_APN"
EOF

    success "Netplan templates created in ${INSTALL_DIR}/config/"
}

# Create systemd service
create_service() {
    info "Creating systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=WARHAMMER Network Overlay Management System
Documentation=https://github.com/your-org/warhammer
After=network-online.target warhammer-dhcp-isolate.service
Wants=network-online.target
Requires=warhammer-dhcp-isolate.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${CONFIG_FILE}
Environment="PYTHONUNBUFFERED=1"
Environment="PYTHONDONTWRITEBYTECODE=1"

# Start command with proper WSGI server
ExecStart=${VENV_DIR}/bin/python -u ${INSTALL_DIR}/app.py

# Restart policy
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=warhammer

# Security - relaxed for network operations
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=read-only
PrivateTmp=true

# Allow network operations
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    success "Systemd service created"
}

# Create sudoers file for service operations
create_sudoers() {
    info "Configuring sudo permissions..."

    cat > "/etc/sudoers.d/warhammer" << 'EOF'
# WARHAMMER sudo permissions
# Allows the web interface to perform system operations

# System control
root ALL=(ALL) NOPASSWD: /sbin/reboot
root ALL=(ALL) NOPASSWD: /sbin/shutdown
root ALL=(ALL) NOPASSWD: /bin/systemctl restart warhammer
root ALL=(ALL) NOPASSWD: /bin/systemctl start warhammer
root ALL=(ALL) NOPASSWD: /bin/systemctl stop warhammer

# Package management for upgrades
root ALL=(ALL) NOPASSWD: /usr/bin/apt update *
root ALL=(ALL) NOPASSWD: /usr/bin/apt upgrade *
root ALL=(ALL) NOPASSWD: /usr/bin/apt autoremove *
root ALL=(ALL) NOPASSWD: /usr/bin/apt-get update *
root ALL=(ALL) NOPASSWD: /usr/bin/apt-get upgrade *
root ALL=(ALL) NOPASSWD: /usr/bin/apt-get autoremove *

# Network configuration
root ALL=(ALL) NOPASSWD: /sbin/ip addr add *
root ALL=(ALL) NOPASSWD: /sbin/ip addr del *
root ALL=(ALL) NOPASSWD: /sbin/ip link set *
root ALL=(ALL) NOPASSWD: /usr/sbin/brctl *
root ALL=(ALL) NOPASSWD: /usr/bin/netplan apply
root ALL=(ALL) NOPASSWD: /sbin/dhclient *
root ALL=(ALL) NOPASSWD: /usr/sbin/ebtables *

# NetworkManager/nmcli for cellular APN management
root ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection add *
root ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection modify *
root ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection delete *
root ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection up *
root ALL=(ALL) NOPASSWD: /usr/bin/nmcli connection down *

# Service management
root ALL=(ALL) NOPASSWD: /bin/systemctl start netbird
root ALL=(ALL) NOPASSWD: /bin/systemctl stop netbird
root ALL=(ALL) NOPASSWD: /bin/systemctl restart netbird
root ALL=(ALL) NOPASSWD: /bin/systemctl start NetworkManager
root ALL=(ALL) NOPASSWD: /bin/systemctl stop NetworkManager
root ALL=(ALL) NOPASSWD: /bin/systemctl restart NetworkManager
root ALL=(ALL) NOPASSWD: /bin/systemctl start docker
root ALL=(ALL) NOPASSWD: /bin/systemctl stop docker
root ALL=(ALL) NOPASSWD: /bin/systemctl restart docker
root ALL=(ALL) NOPASSWD: /bin/systemctl start warhammer-dhcp-isolate
root ALL=(ALL) NOPASSWD: /bin/systemctl stop warhammer-dhcp-isolate
root ALL=(ALL) NOPASSWD: /bin/systemctl restart warhammer-dhcp-isolate
EOF

    chmod 440 /etc/sudoers.d/warhammer

    success "Sudo permissions configured"
}

# Set file permissions
set_permissions() {
    info "Setting file permissions..."

    # Create scripts directory
    mkdir -p "${INSTALL_DIR}/scripts"

    chown -R root:root "${INSTALL_DIR}"
    chmod -R 755 "${INSTALL_DIR}"
    chmod 600 "${CONFIG_FILE}"

    # Make scripts executable
    find "${INSTALL_DIR}/scripts" -name "*.sh" -exec chmod +x {} \;

    success "Permissions configured"
}

# Enable and start services
enable_service() {
    info "Enabling services..."

    systemctl enable warhammer-dhcp-isolate.service
    systemctl enable "${SERVICE_NAME}"

    success "Services enabled to start at boot"
}

# Start services
start_service() {
    info "Starting WARHAMMER services..."

    # Start DHCP isolation first
    systemctl start warhammer-dhcp-isolate.service || warn "DHCP isolation may not be needed yet"

    # Start main service
    systemctl start "${SERVICE_NAME}"

    # Wait a moment for startup
    sleep 3

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        success "WARHAMMER service is running"
    else
        warn "Service may have failed to start."
        echo ""
        echo -e "${YELLOW}Checking logs...${NC}"
        journalctl -u ${SERVICE_NAME} -n 20 --no-pager
        echo ""
        echo -e "${YELLOW}To debug further:${NC}"
        echo "  journalctl -u ${SERVICE_NAME} -f"
        echo "  ${VENV_DIR}/bin/python ${INSTALL_DIR}/app.py"
    fi
}

# Print completion message
print_complete() {
    local IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            WARHAMMER Installation Complete!               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Web Interface:${NC}  http://${IP}:${DEFAULT_PORT}"
    echo -e "  ${CYAN}Configuration:${NC}  ${CONFIG_FILE}"
    echo -e "  ${CYAN}Install Path:${NC}   ${INSTALL_DIR}"
    echo ""
    echo -e "  ${YELLOW}Service Commands:${NC}"
    echo -e "    sudo systemctl status ${SERVICE_NAME}"
    echo -e "    sudo systemctl restart ${SERVICE_NAME}"
    echo -e "    sudo systemctl stop ${SERVICE_NAME}"
    echo -e "    sudo journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo -e "  ${YELLOW}DHCP Isolation:${NC}"
    echo -e "    sudo systemctl status warhammer-dhcp-isolate"
    echo -e "    ${INSTALL_DIR}/scripts/dhcp-isolate.sh status"
    echo ""
    echo -e "  ${YELLOW}Netplan Templates:${NC}"
    echo -e "    ${INSTALL_DIR}/config/netplan-bridge-dhcp.yaml"
    echo -e "    ${INSTALL_DIR}/config/netplan-unbridged.yaml"
    echo ""
    echo -e "  ${YELLOW}Default Credentials:${NC}"
    echo -e "    Username: admin"
    echo -e "    Password: warhammer"
    echo ""
    echo -e "  ${RED}Important:${NC} Edit ${CONFIG_FILE} with your settings!"
    echo ""
}

# Uninstall function
uninstall() {
    print_banner
    info "Uninstalling WARHAMMER..."

    # Stop and disable services
    systemctl stop warhammer-dhcp-isolate 2>/dev/null || true
    systemctl disable warhammer-dhcp-isolate 2>/dev/null || true
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

    # Remove service files
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f /etc/systemd/system/warhammer-dhcp-isolate.service
    systemctl daemon-reload

    # Clear ebtables rules
    ebtables -t broute -F 2>/dev/null || true
    ebtables -F 2>/dev/null || true

    # Remove sudoers
    rm -f /etc/sudoers.d/warhammer

    # Remove install directory
    rm -rf "${INSTALL_DIR}"

    # Optionally remove config
    read -p "Remove configuration file? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf /etc/warhammer
        success "Configuration removed"
    fi

    # Remove user
    if id "${SERVICE_USER}" &>/dev/null; then
        userdel "${SERVICE_USER}" 2>/dev/null || true
    fi

    success "WARHAMMER uninstalled"
}

# Main installation flow
main() {
    print_banner

    # Handle uninstall flag
    if [[ "${1}" == "--uninstall" ]] || [[ "${1}" == "-u" ]]; then
        check_root
        uninstall
        exit 0
    fi

    # Handle help flag
    if [[ "${1}" == "--help" ]] || [[ "${1}" == "-h" ]]; then
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --uninstall, -u    Uninstall WARHAMMER"
        echo "  --help, -h         Show this help message"
        echo ""
        exit 0
    fi

    check_root
    detect_source

    echo ""
    info "Starting WARHAMMER installation..."
    echo ""

    install_dependencies
    create_user
    install_application
    setup_venv
    create_config
    set_permissions
    setup_dhcp_isolation
    create_netplan_config
    create_service
    create_sudoers
    enable_service
    start_service

    print_complete
}

# Run main
main "$@"
