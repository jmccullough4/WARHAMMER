#!/bin/bash
#
# WARHAMMER Installation Script
# Network Overlay Management System
#
# This script installs WARHAMMER as a systemd service
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

    apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        git \
        iperf3 \
        gpsd \
        gpsd-clients \
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

    python3 -m venv "${VENV_DIR}"

    # Upgrade pip
    "${VENV_DIR}/bin/pip" install --upgrade pip -q

    # Install requirements
    if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
        "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q
    else
        # Install core dependencies
        "${VENV_DIR}/bin/pip" install \
            flask \
            flask-socketio \
            requests \
            psutil \
            eventlet \
            -q
    fi

    success "Python environment configured"
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
MANAGEMENT_INTERFACE_2=
MANAGEMENT_INTERFACE_3=
BRIDGE_INTERFACE=br0
WWAN_INTERFACE=wwan0
WIFI_INTERFACE=wlo1
PORT_1_INTERFACE=eth0
PORT_2_INTERFACE=eth1
BRIDGED_CIDR=

# Netplan Configuration
BASE_NETPLAN=/etc/netplan/01-network-manager-all.yaml
EOF
        success "Configuration file created: ${CONFIG_FILE}"
        warn "Edit ${CONFIG_FILE} to configure your installation"
    fi
}

# Create systemd service
create_service() {
    info "Creating systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=WARHAMMER Network Overlay Management System
Documentation=https://github.com/your-org/warhammer
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_FILE}
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=read-only
PrivateTmp=true

# Allow network operations
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
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
root ALL=(ALL) NOPASSWD: /usr/bin/netplan apply

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
EOF

    chmod 440 /etc/sudoers.d/warhammer

    success "Sudo permissions configured"
}

# Set file permissions
set_permissions() {
    info "Setting file permissions..."

    chown -R root:root "${INSTALL_DIR}"
    chmod -R 755 "${INSTALL_DIR}"
    chmod 600 "${CONFIG_FILE}"

    success "Permissions configured"
}

# Enable and start service
enable_service() {
    info "Enabling service..."

    systemctl enable "${SERVICE_NAME}"

    success "Service enabled to start at boot"
}

# Start service
start_service() {
    info "Starting WARHAMMER service..."

    systemctl start "${SERVICE_NAME}"

    # Wait a moment for startup
    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        success "WARHAMMER service is running"
    else
        warn "Service may have failed to start. Check: journalctl -u ${SERVICE_NAME}"
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

    # Stop and disable service
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

    # Remove service file
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload

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
    create_service
    create_sudoers
    set_permissions
    enable_service
    start_service

    print_complete
}

# Run main
main "$@"
