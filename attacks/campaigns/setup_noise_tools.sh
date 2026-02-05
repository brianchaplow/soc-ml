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

install_certipy() {
    log_info "Installing Certipy (AD CS attacks)..."
    pip3 install certipy-ad 2>/dev/null || pipx install certipy-ad 2>/dev/null || true
    log_success "Certipy installed"
}

install_ffuf() {
    log_info "Installing ffuf (fast web fuzzer)..."

    if command -v ffuf &> /dev/null; then
        log_warn "ffuf already installed"
    else
        # Install via Go
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true

        if [[ -f /root/go/bin/ffuf ]]; then
            ln -sf /root/go/bin/ffuf /usr/local/bin/ffuf
        fi

        # Fallback to apt
        if ! command -v ffuf &> /dev/null; then
            apt-get install -y ffuf 2>/dev/null || true
        fi
    fi

    log_success "ffuf installed"
}

install_havoc() {
    log_info "Installing Havoc C2..."

    if [[ -d /opt/havoc ]]; then
        log_warn "Havoc already exists at /opt/havoc"
    else
        # Install dependencies
        apt-get install -y git build-essential apt-utils cmake libfontconfig1 \
            libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev \
            libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev \
            libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser \
            qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev \
            qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev \
            python3-dev libboost-all-dev mingw-w64 nasm 2>/dev/null || true

        git clone https://github.com/HavocFramework/Havoc.git /opt/havoc
        cd /opt/havoc

        # Build teamserver
        cd teamserver
        go mod download golang.org/x/sys
        go mod download github.com/ugorji/go
        cd ..

        # Build client
        make ts-build 2>/dev/null || log_warn "Havoc teamserver build may need manual completion"
        make client-build 2>/dev/null || log_warn "Havoc client build may need manual completion"
    fi

    log_success "Havoc installed to /opt/havoc/"
}

install_hashcat() {
    log_info "Installing hashcat..."
    apt-get install -y hashcat hashcat-utils 2>/dev/null || true
    log_success "hashcat installed"
}

install_coercer() {
    log_info "Installing Coercer (Windows auth coercion)..."
    pip3 install coercer 2>/dev/null || pipx install coercer 2>/dev/null || true
    log_success "Coercer installed"
}

install_petitpotam() {
    log_info "Installing PetitPotam..."

    if [[ -d /opt/PetitPotam ]]; then
        log_warn "PetitPotam already exists"
    else
        git clone https://github.com/topotam/PetitPotam.git /opt/PetitPotam
    fi

    log_success "PetitPotam installed to /opt/PetitPotam/"
}

install_ldapdomaindump() {
    log_info "Installing ldapdomaindump..."
    pip3 install ldapdomaindump 2>/dev/null || pipx install ldapdomaindump 2>/dev/null || true
    log_success "ldapdomaindump installed"
}

install_httpx() {
    log_info "Installing httpx (HTTP toolkit)..."

    if command -v httpx &> /dev/null; then
        log_warn "httpx already installed"
    else
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true

        if [[ -f /root/go/bin/httpx ]]; then
            ln -sf /root/go/bin/httpx /usr/local/bin/httpx
        fi
    fi

    log_success "httpx installed"
}

install_subfinder() {
    log_info "Installing subfinder (subdomain discovery)..."

    if command -v subfinder &> /dev/null; then
        log_warn "subfinder already installed"
    else
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true

        if [[ -f /root/go/bin/subfinder ]]; then
            ln -sf /root/go/bin/subfinder /usr/local/bin/subfinder
        fi
    fi

    log_success "subfinder installed"
}

install_feroxbuster() {
    log_info "Installing feroxbuster..."
    apt-get install -y feroxbuster 2>/dev/null || true
    log_success "feroxbuster installed"
}

install_cewl() {
    log_info "Installing CeWL (custom wordlist generator)..."
    apt-get install -y cewl 2>/dev/null || true
    log_success "CeWL installed"
}

install_name_that_hash() {
    log_info "Installing name-that-hash..."
    pip3 install name-that-hash 2>/dev/null || pipx install name-that-hash 2>/dev/null || true
    log_success "name-that-hash installed"
}

install_dalfox() {
    log_info "Installing dalfox (XSS scanner)..."

    if command -v dalfox &> /dev/null; then
        log_warn "dalfox already installed"
    else
        go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true

        if [[ -f /root/go/bin/dalfox ]]; then
            ln -sf /root/go/bin/dalfox /usr/local/bin/dalfox
        fi
    fi

    log_success "dalfox installed"
}

install_commix() {
    log_info "Installing commix (command injection)..."
    apt-get install -y commix 2>/dev/null || true
    log_success "commix installed"
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
        "certipy"
        "ffuf"
        "hashcat"
        "coercer"
        "httpx"
        "subfinder"
        "feroxbuster"
        "cewl"
        "nth"
        "dalfox"
        "commix"
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
    [[ -d /opt/havoc ]] && log_success "Havoc C2: OK" || log_error "Havoc C2: MISSING"
    [[ -d /opt/PetitPotam ]] && log_success "PetitPotam: OK" || log_error "PetitPotam: MISSING"

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
    echo ""
    echo "  C2 Frameworks:"
    echo "    - Sliver C2 (command & control)"
    echo "    - Havoc C2 (Cobalt Strike alternative)"
    echo ""
    echo "  Scanning & Enumeration:"
    echo "    - Nuclei (template-based scanner)"
    echo "    - ffuf (fast web fuzzer)"
    echo "    - feroxbuster (recursive content discovery)"
    echo "    - httpx (HTTP probing toolkit)"
    echo "    - subfinder (subdomain discovery)"
    echo "    - dalfox (XSS scanner)"
    echo ""
    echo "  Active Directory:"
    echo "    - Kerbrute (Kerberos enumeration)"
    echo "    - Certipy (AD CS attacks)"
    echo "    - Coercer (auth coercion)"
    echo "    - PetitPotam (NTLM relay)"
    echo "    - ldapdomaindump (LDAP enum)"
    echo "    - BloodHound + SharpHound"
    echo "    - Rubeus (Kerberos attacks)"
    echo ""
    echo "  Tunneling:"
    echo "    - dnscat2 (DNS tunneling)"
    echo "    - iodine (DNS tunneling)"
    echo "    - ptunnel-ng (ICMP tunneling)"
    echo ""
    echo "  Password/Hash:"
    echo "    - hashcat (GPU cracking)"
    echo "    - name-that-hash (hash identification)"
    echo "    - CeWL (custom wordlists)"
    echo ""
    echo "  Exploitation:"
    echo "    - commix (command injection)"
    echo ""
    echo "Tool locations:"
    echo "  - /opt/dnscat2/"
    echo "  - /opt/ptunnel-ng/"
    echo "  - /opt/rubeus/"
    echo "  - /opt/sharphound/"
    echo "  - /opt/havoc/"
    echo "  - /opt/PetitPotam/"
    echo ""
    echo "Next steps:"
    echo "  1. Start BloodHound: neo4j console & bloodhound"
    echo "  2. Generate Sliver implant: sliver-server"
    echo "  3. Start Havoc: cd /opt/havoc && ./havoc server"
    echo "  4. Run campaign: ./campaigns/runner.sh --config campaigns/configs/maximum_noise_48h.yaml"
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
    install_certipy
    install_ffuf
    install_havoc
    install_hashcat
    install_coercer
    install_petitpotam
    install_ldapdomaindump
    install_httpx
    install_subfinder
    install_feroxbuster
    install_cewl
    install_name_that_hash
    install_dalfox
    install_commix
    setup_wordlists
    verify_tools
    print_summary
}

main "$@"
