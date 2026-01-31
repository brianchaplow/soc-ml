#!/bin/bash
###############################################################################
# Target VM Setup Script
# Run this on the Docker host that has VLAN 40 access
#
# Usage:
#   ./setup.sh              # Full setup
#   ./setup.sh --check      # Just verify targets are up
#   ./setup.sh --teardown   # Stop and remove everything
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

cd "$SCRIPT_DIR"

# Load env
if [[ ! -f .env ]]; then
    echo -e "${YELLOW}No .env file found. Copying from .env.example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}Edit .env to set PARENT_IFACE for your host, then re-run.${NC}"
    exit 1
fi
source .env

check_targets() {
    echo -e "${CYAN}Checking target accessibility from this host...${NC}"
    local targets=(
        "${WORDPRESS_IP:-10.10.40.30}:80:WordPress"
        "${CRAPI_IP:-10.10.40.31}:8080:crAPI"
        "${SERVICES_IP:-10.10.40.32}:21:FTP"
        "${HONEYPOT_IP:-10.10.40.33}:80:WAF"
    )

    for entry in "${targets[@]}"; do
        IFS=':' read -r ip port name <<< "$entry"
        if timeout 3 bash -c "echo > /dev/tcp/$ip/$port" 2>/dev/null; then
            echo -e "  ${GREEN}[UP]${NC}   $name ($ip:$port)"
        else
            echo -e "  ${RED}[DOWN]${NC} $name ($ip:$port)"
        fi
    done
}

teardown() {
    echo -e "${YELLOW}Tearing down target containers...${NC}"
    docker compose down -v
    echo -e "${GREEN}Done.${NC}"
}

setup() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           TARGET VM DEPLOYMENT                                ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo -e "║  Parent interface:  ${GREEN}${PARENT_IFACE}${CYAN}"
    echo -e "║  Subnet:            ${SUBNET}"
    echo -e "║  WordPress:         ${WORDPRESS_IP}:80"
    echo -e "║  crAPI:             ${CRAPI_IP}:8080"
    echo -e "║  Vuln Services:     ${SERVICES_IP}:21,25,161"
    echo -e "║  WAF/Honeypot:      ${HONEYPOT_IP}:80"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Pre-flight checks
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}Docker not installed. Install docker first.${NC}"
        exit 1
    fi

    if ! docker compose version &>/dev/null; then
        echo -e "${RED}Docker Compose V2 not available. Install docker-compose-plugin.${NC}"
        exit 1
    fi

    # Verify network interface exists
    if ! ip link show "$PARENT_IFACE" &>/dev/null; then
        echo -e "${RED}Interface '$PARENT_IFACE' not found.${NC}"
        echo "Available interfaces:"
        ip link show | grep -E "^[0-9]+:" | awk '{print "  " $2}'
        exit 1
    fi

    echo -e "${GREEN}Pulling images...${NC}"
    docker compose pull

    echo -e "${GREEN}Starting containers...${NC}"
    docker compose up -d

    echo ""
    echo -e "${YELLOW}Waiting 30s for services to initialize...${NC}"
    sleep 30

    echo ""
    docker compose ps

    echo ""
    check_targets

    echo ""
    echo -e "${CYAN}WordPress first-time setup:${NC}"
    echo "  Visit http://${WORDPRESS_IP}/wp-admin/install.php"
    echo "  Or run: curl -s 'http://${WORDPRESS_IP}/wp-admin/install.php?step=2' \\"
    echo "    --data 'weblog_title=VulnPress&user_name=admin&admin_password=admin&admin_password2=admin&admin_email=admin@example.com&blog_public=0&Submit=Install+WordPress'"
    echo ""
    echo -e "${GREEN}Targets deployed. Attack from sear (10.10.20.20).${NC}"
}

case "${1:-}" in
    --check)   check_targets ;;
    --teardown) teardown ;;
    *)         setup ;;
esac
