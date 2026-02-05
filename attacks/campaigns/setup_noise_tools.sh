#!/bin/bash
###############################################################################
# Setup Script for Maximum Noise Campaign
# Installs additional attack tools not included in base Kali
#
# Run as: sudo ./setup_noise_tools.sh
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

install_apt_packages() {
    log_info "Installing APT packages..."

    apt-get update

    # Core tools (should already be on Kali, but ensure latest)
    apt-get install -y \
        nmap \
        masscan \
        hydra \
        medusa \
        patator \
        nikto \
        dirb \
        gobuster \
        sqlmap \
        metasploit-framework \
        crackmapexec \
        impacket-scripts \
        python3-impacket \
        smbclient \
        enum4linux-ng \
        snmp \
        snmpd \
        dnsutils \
        ldap-utils \
        responder \
        evil-winrm \
        bloodhound \
        neo4j \
        seclists \
        wordlists

    log_success "APT packages installed"
}

install_nuclei() {
    log_info "Installing Nuclei..."

    if command -v nuclei &> /dev/null; then
        log_warn "Nuclei already installed, updating..."
        nuclei -update
        nuclei -update-templates
    else
        # Install via Go
        if ! command -v go &> /dev/null; then
            apt-get install -y golang
        fi

        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

        # Add to path
        if [[ -f /root/go/bin/nuclei ]]; then
            ln -sf /root/go/bin/nuclei /usr/local/bin/nuclei
        fi

        # Download templates
        nuclei -update-templates
    fi

    log_success "Nuclei installed"
}

install_kerbrute() {
    log_info "Installing Kerbrute..."

    KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"

    wget -q "$KERBRUTE_URL" -O /usr/local/bin/kerbrute
    chmod +x /usr/local/bin/kerbrute

    log_success "Kerbrute installed"
}

install_sliver() {
    log_info "Installing Sliver C2..."

    if command -v sliver-server &> /dev/null; then
        log_warn "Sliver already installed"
    else
        # One-liner installer from BishopFox
        curl https://sliver.sh/install | bash
    fi

    log_success "Sliver C2 installed"
}

install_dnscat2() {
    log_info "Installing dnscat2..."

    if [[ -d /opt/dnscat2 ]]; then
        log_warn "dnscat2 already exists at /opt/dnscat2"
    else
        git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2
        cd /opt/dnscat2/server
        gem install bundler
        bundle install
    fi

    log_success "dnscat2 installed"
}

install_iodine() {
    log_info "Installing iodine DNS tunnel..."

    apt-get install -y iodine

    log_success "iodine installed"
}

install_ptunnel() {
    log_info "Installing ptunnel-ng (ICMP tunnel)..."

    if [[ -d /opt/ptunnel-ng ]]; then
        log_warn "ptunnel-ng already exists"
    else
        git clone https://github.com/utoni/ptunnel-ng.git /opt/ptunnel-ng
        cd /opt/ptunnel-ng
        ./autogen.sh
        ./configure
        make
        make install
    fi

    log_success "ptunnel-ng installed"
}

install_rubeus() {
    log_info "Setting up Rubeus (pre-compiled)..."

    # Rubeus is a .NET tool, we'll download pre-compiled
    mkdir -p /opt/rubeus
    RUBEUS_URL="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"

    wget -q "$RUBEUS_URL" -O /opt/rubeus/Rubeus.exe

    log_success "Rubeus downloaded to /opt/rubeus/"
    log_warn "Rubeus requires Windows or mono to execute"
}

install_sharphound() {
    log_info "Setting up SharpHound..."

    mkdir -p /opt/sharphound

    # Download latest SharpHound
    SHARPHOUND_URL=$(curl -s https://api.github.com/repos/BloodHoundAD/SharpHound/releases/latest | grep "browser_download_url.*zip" | head -1 | cut -d '"' -f 4)

    if [[ -n "$SHARPHOUND_URL" ]]; then
        wget -q "$SHARPHOUND_URL" -O /opt/sharphound/SharpHound.zip
        unzip -o /opt/sharphound/SharpHound.zip -d /opt/sharphound/
        rm /opt/sharphound/SharpHound.zip
        log_success "SharpHound downloaded to /opt/sharphound/"
    else
        log_error "Could not fetch SharpHound URL"
    fi
}

setup_wordlists() {
    log_info "Setting up wordlists..."

    WORDLIST_DIR="/home/butcher/soc-ml/attacks/wordlists"
    mkdir -p "$WORDLIST_DIR"

    # Link common wordlists
    if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
        gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    fi

    if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
        ln -sf /usr/share/wordlists/rockyou.txt "$WORDLIST_DIR/rockyou.txt"
    fi

    # SecLists
    if [[ -d /usr/share/seclists ]]; then
        ln -sf /usr/share/seclists/Usernames/top-usernames-shortlist.txt "$WORDLIST_DIR/users_short.txt"
        ln -sf /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt "$WORDLIST_DIR/passwords_10k.txt"
        ln -sf /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt "$WORDLIST_DIR/dirs_big.txt"
        ln -sf /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt "$WORDLIST_DIR/subdomains_5k.txt"
    fi

    log_success "Wordlists configured"
}

verify_tools() {
    log_info "Verifying installed tools..."

    TOOLS=(
        "nmap"
        "masscan"
        "hydra"
        "medusa"
        "nikto"
        "sqlmap"
        "msfconsole"
        "crackmapexec"
        "impacket-psexec"
        "enum4linux-ng"
        "responder"
        "evil-winrm"
        "nuclei"
        "kerbrute"
    )

    MISSING=()

    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_success "$tool: OK"
        else
            log_error "$tool: MISSING"
            MISSING+=("$tool")
        fi
    done

    # Check directory-based tools
    [[ -d /opt/dnscat2 ]] && log_success "dnscat2: OK" || log_error "dnscat2: MISSING"
    [[ -f /opt/rubeus/Rubeus.exe ]] && log_success "Rubeus: OK" || log_error "Rubeus: MISSING"
    [[ -d /opt/sharphound ]] && log_success "SharpHound: OK" || log_error "SharpHound: MISSING"

    if [[ ${#MISSING[@]} -gt 0 ]]; then
        log_warn "Some tools are missing. Campaign may have reduced functionality."
    else
        log_success "All core tools verified!"
    fi
}

print_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Setup Complete!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Installed tools:"
    echo "  - Nuclei (template-based scanner)"
    echo "  - Kerbrute (Kerberos enumeration)"
    echo "  - Sliver C2 (command & control)"
    echo "  - dnscat2 (DNS tunneling)"
    echo "  - iodine (DNS tunneling)"
    echo "  - ptunnel-ng (ICMP tunneling)"
    echo "  - Rubeus (Kerberos attacks)"
    echo "  - SharpHound (BloodHound collector)"
    echo ""
    echo "Tool locations:"
    echo "  - /opt/dnscat2/"
    echo "  - /opt/ptunnel-ng/"
    echo "  - /opt/rubeus/"
    echo "  - /opt/sharphound/"
    echo ""
    echo "Next steps:"
    echo "  1. Start BloodHound: neo4j console & bloodhound"
    echo "  2. Generate Sliver implant: sliver-server"
    echo "  3. Run campaign: ./campaigns/runner.sh --config campaigns/configs/maximum_noise_48h.yaml"
    echo ""
}

main() {
    check_root

    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║        MAXIMUM NOISE CAMPAIGN - TOOL SETUP                    ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    install_apt_packages
    install_nuclei
    install_kerbrute
    install_sliver
    install_dnscat2
    install_iodine
    install_ptunnel
    install_rubeus
    install_sharphound
    setup_wordlists
    verify_tools
    print_summary
}

main "$@"
