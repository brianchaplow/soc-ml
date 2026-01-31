#!/bin/bash
###############################################################################
# Purple Team Attack Wrapper
# 
# ALWAYS use this script to run attacks - it handles logging!
#
# Usage: ./run_attack.sh <attack_type> ["notes"]
#
# Example: ./run_attack.sh web_sqli_union "Testing DVWA low security"
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/attack_log.csv"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
RESULTS_DIR="${SCRIPT_DIR}/results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Source configurations
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

# Sear's IP (attack source)
SOURCE_IP="10.10.20.20"

# =============================================================================
# ATTACK DEFINITIONS
# =============================================================================
# Format: ATTACK_NAME="category|subcategory|technique_id|tool|target_ip|target_port|service"

declare -A ATTACKS

# Web Application Attacks (DVWA - 10.10.40.10)
ATTACKS[web_sqli_union]="web|sqli_union|T1190|sqlmap|10.10.40.10|80|http"
ATTACKS[web_sqli_blind]="web|sqli_blind|T1190|sqlmap|10.10.40.10|80|http"
ATTACKS[web_sqli_time]="web|sqli_time|T1190|sqlmap|10.10.40.10|80|http"
ATTACKS[web_sqli_error]="web|sqli_error|T1190|sqlmap|10.10.40.10|80|http"
ATTACKS[web_xss_reflected]="web|xss_reflected|T1189|manual|10.10.40.10|80|http"
ATTACKS[web_xss_stored]="web|xss_stored|T1189|manual|10.10.40.10|80|http"
ATTACKS[web_lfi]="web|lfi|T1083|manual|10.10.40.10|80|http"
ATTACKS[web_command_injection]="web|command_injection|T1059|manual|10.10.40.10|80|http"
ATTACKS[web_dirbusting]="web|directory_enum|T1083|gobuster|10.10.40.10|80|http"
ATTACKS[web_nikto]="web|vuln_scan|T1595|nikto|10.10.40.10|80|http"

# Web Attacks (Juice Shop - 10.10.40.10)
ATTACKS[juice_sqli]="web|sqli_juice|T1190|sqlmap|10.10.40.10|3000|http"
ATTACKS[juice_xss]="web|xss_juice|T1189|manual|10.10.40.10|3000|http"
ATTACKS[juice_dirbusting]="web|directory_enum|T1083|gobuster|10.10.40.10|3000|http"

# Reconnaissance
ATTACKS[recon_syn]="recon|syn_scan|T1046|nmap|10.10.40.0/24|*|network"
ATTACKS[recon_full]="recon|tcp_connect|T1046|nmap|10.10.40.0/24|*|network"
ATTACKS[recon_udp]="recon|udp_scan|T1046|nmap|10.10.40.0/24|*|network"
ATTACKS[recon_version]="recon|version_detect|T1046|nmap|10.10.40.10|*|network"
ATTACKS[recon_os]="recon|os_fingerprint|T1082|nmap|10.10.40.10|*|network"
ATTACKS[recon_aggressive]="recon|aggressive_scan|T1046|nmap|10.10.40.10|*|network"

# Brute Force (Metasploitable - 10.10.40.20)
ATTACKS[brute_ssh]="brute|ssh_password|T1110.001|hydra|10.10.40.20|22|ssh"
ATTACKS[brute_ftp]="brute|ftp_password|T1110.001|hydra|10.10.40.20|21|ftp"
ATTACKS[brute_telnet]="brute|telnet_password|T1110.001|hydra|10.10.40.20|23|telnet"
ATTACKS[brute_web_dvwa]="brute|web_form|T1110.001|hydra|10.10.40.10|80|http"

# Exploitation (Metasploitable - 10.10.40.20)
ATTACKS[exploit_vsftpd]="exploit|vsftpd_backdoor|T1190|metasploit|10.10.40.20|21|ftp"
ATTACKS[exploit_distcc]="exploit|distcc_exec|T1210|metasploit|10.10.40.20|3632|distcc"
ATTACKS[exploit_samba]="exploit|samba_usermap|T1210|metasploit|10.10.40.20|139|smb"
ATTACKS[exploit_postgres]="exploit|postgres_payload|T1190|metasploit|10.10.40.20|5432|postgres"
ATTACKS[exploit_tomcat]="exploit|tomcat_mgr_upload|T1190|metasploit|10.10.40.20|8180|http"
ATTACKS[exploit_java_rmi]="exploit|java_rmi|T1210|metasploit|10.10.40.20|1099|rmi"

# C2 Simulation
ATTACKS[c2_beacon_http]="c2|http_beacon|T1071.001|custom|10.10.40.10|80|http"
ATTACKS[c2_beacon_dns]="c2|dns_beacon|T1071.004|custom|10.10.40.10|53|dns"
ATTACKS[c2_exfil_http]="c2|http_exfil|T1048.003|custom|10.10.40.10|80|http"

# =============================================================================
# FUNCTIONS
# =============================================================================

print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║          PURPLE TEAM ATTACK FRAMEWORK - SOC-ML                ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

list_attacks() {
    echo -e "${YELLOW}Available Attacks:${NC}"
    echo ""
    echo "Web Application:"
    echo "  web_sqli_union      - UNION-based SQL injection (DVWA)"
    echo "  web_sqli_blind      - Blind SQL injection (DVWA)"
    echo "  web_sqli_time       - Time-based SQL injection (DVWA)"
    echo "  web_sqli_error      - Error-based SQL injection (DVWA)"
    echo "  web_xss_reflected   - Reflected XSS (DVWA)"
    echo "  web_xss_stored      - Stored XSS (DVWA)"
    echo "  web_lfi             - Local File Inclusion (DVWA)"
    echo "  web_command_injection - Command Injection (DVWA)"
    echo "  web_dirbusting      - Directory enumeration (DVWA)"
    echo "  web_nikto           - Nikto vulnerability scan (DVWA)"
    echo "  juice_sqli          - SQL injection (Juice Shop)"
    echo "  juice_xss           - XSS attacks (Juice Shop)"
    echo "  juice_dirbusting    - Directory enumeration (Juice Shop)"
    echo ""
    echo "Reconnaissance:"
    echo "  recon_syn           - SYN scan (Target subnet)"
    echo "  recon_full          - Full TCP connect scan"
    echo "  recon_udp           - UDP scan"
    echo "  recon_version       - Version detection"
    echo "  recon_os            - OS fingerprinting"
    echo "  recon_aggressive    - Aggressive scan (-A)"
    echo ""
    echo "Brute Force:"
    echo "  brute_ssh           - SSH brute force (Metasploitable)"
    echo "  brute_ftp           - FTP brute force (Metasploitable)"
    echo "  brute_telnet        - Telnet brute force (Metasploitable)"
    echo "  brute_web_dvwa      - DVWA login brute force"
    echo ""
    echo "Exploitation:"
    echo "  exploit_vsftpd      - VSFTPD backdoor (Metasploitable)"
    echo "  exploit_distcc      - DistCC exploit (Metasploitable)"
    echo "  exploit_samba       - Samba usermap_script (Metasploitable)"
    echo "  exploit_postgres    - PostgreSQL payload (Metasploitable)"
    echo "  exploit_tomcat      - Tomcat manager upload (Metasploitable)"
    echo "  exploit_java_rmi    - Java RMI exploit (Metasploitable)"
    echo ""
    echo "C2 Simulation:"
    echo "  c2_beacon_http      - HTTP beaconing simulation"
    echo "  c2_beacon_dns       - DNS beaconing simulation"
    echo "  c2_exfil_http       - HTTP exfiltration simulation"
    echo ""
}

usage() {
    echo "Usage: $0 <attack_type> [\"notes\"]"
    echo ""
    echo "Options:"
    echo "  -l, --list     List available attacks"
    echo "  -h, --help     Show this help"
    echo ""
    echo "Example:"
    echo "  $0 web_sqli_union \"Testing DVWA with low security\""
    echo ""
}

log_attack() {
    local attack_id="$1"
    local ts_start="$2"
    local ts_end="$3"
    local category="$4"
    local subcategory="$5"
    local technique_id="$6"
    local tool="$7"
    local target_ip="$8"
    local target_port="$9"
    local service="${10}"
    local success="${11}"
    local notes="${12}"
    
    echo "${attack_id},${ts_start},${ts_end},${category},${subcategory},${technique_id},${tool},${SOURCE_IP},${target_ip},${target_port},${service},${success},\"${notes}\"" >> "${LOG_FILE}"
}

# =============================================================================
# MAIN
# =============================================================================

print_banner

# Handle arguments
case "${1:-}" in
    -l|--list)
        list_attacks
        exit 0
        ;;
    -h|--help|"")
        usage
        list_attacks
        exit 0
        ;;
esac

ATTACK_TYPE="$1"
NOTES="${2:-}"

# Validate attack type
if [[ -z "${ATTACKS[$ATTACK_TYPE]+isset}" ]]; then
    echo -e "${RED}Error: Unknown attack type '${ATTACK_TYPE}'${NC}"
    echo ""
    echo "Use '$0 --list' to see available attacks"
    exit 1
fi

# Parse attack definition
IFS='|' read -r CATEGORY SUBCATEGORY TECHNIQUE_ID TOOL TARGET_IP TARGET_PORT SERVICE <<< "${ATTACKS[$ATTACK_TYPE]}"

# Generate attack ID
ATTACK_ID="ATK-$(date +%Y%m%d-%H%M%S)"

# Create results directory for this attack
ATTACK_RESULTS="${RESULTS_DIR}/${ATTACK_ID}"
mkdir -p "${ATTACK_RESULTS}"

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ATTACK: ${ATTACK_TYPE}${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  ID:        ${ATTACK_ID}${NC}"
echo -e "${GREEN}║  Category:  ${CATEGORY}/${SUBCATEGORY}${NC}"
echo -e "${GREEN}║  Technique: ${TECHNIQUE_ID}${NC}"
echo -e "${GREEN}║  Tool:      ${TOOL}${NC}"
echo -e "${GREEN}║  Source:    ${SOURCE_IP}${NC}"
echo -e "${GREEN}║  Target:    ${TARGET_IP}:${TARGET_PORT} (${SERVICE})${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Safety confirmation
echo -e "${YELLOW}⚠️  Confirm target is in VLAN 40 (Targets network)${NC}"
read -p "Proceed with attack? (y/N): " confirm
if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
    echo -e "${RED}Attack cancelled${NC}"
    exit 1
fi

# Record start time
TS_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo ""
echo -e "${BLUE}[${TS_START}] Attack starting...${NC}"
echo ""

# Execute the appropriate attack script
ATTACK_SCRIPT="${SCRIPTS_DIR}/${ATTACK_TYPE}.sh"
SUCCESS="true"

if [[ -f "${ATTACK_SCRIPT}" ]]; then
    # Run the specific attack script
    if ! bash "${ATTACK_SCRIPT}" "${TARGET_IP}" "${TARGET_PORT}" "${ATTACK_RESULTS}" 2>&1 | tee "${ATTACK_RESULTS}/output.log"; then
        SUCCESS="false"
    fi
else
    # Fallback to generic attack based on tool
    echo -e "${YELLOW}No specific script found, using generic ${TOOL} attack...${NC}"
    
    case "${TOOL}" in
        sqlmap)
            echo "Running sqlmap (you may need to provide cookies)..."
            echo "Command: sqlmap -u \"http://${TARGET_IP}/vulnerabilities/sqli/?id=1&Submit=Submit\" --batch --level=2"
            echo ""
            echo -e "${YELLOW}Run this command manually and press Enter when done:${NC}"
            read -p ""
            ;;
        nmap)
            case "${SUBCATEGORY}" in
                syn_scan)
                    nmap -sS -T4 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
                tcp_connect)
                    nmap -sT -T4 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
                udp_scan)
                    nmap -sU -T4 --top-ports 100 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
                version_detect)
                    nmap -sV -T4 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
                os_fingerprint)
                    nmap -O -T4 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
                aggressive_scan)
                    nmap -A -T4 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
                *)
                    nmap -sS -T4 "${TARGET_IP}" -oN "${ATTACK_RESULTS}/nmap.txt"
                    ;;
            esac
            ;;
        hydra)
            echo "Running hydra brute force..."
            echo "Command: hydra -l admin -P /usr/share/wordlists/rockyou.txt ${TARGET_IP} ${SERVICE}"
            echo ""
            echo -e "${YELLOW}Run this command manually and press Enter when done:${NC}"
            read -p ""
            ;;
        gobuster)
            gobuster dir -u "http://${TARGET_IP}:${TARGET_PORT}/" -w /usr/share/wordlists/dirb/common.txt -o "${ATTACK_RESULTS}/gobuster.txt" || SUCCESS="false"
            ;;
        nikto)
            nikto -h "http://${TARGET_IP}:${TARGET_PORT}/" -o "${ATTACK_RESULTS}/nikto.txt" || SUCCESS="false"
            ;;
        metasploit)
            echo -e "${YELLOW}Metasploit attack - launch msfconsole and run appropriate module${NC}"
            echo "Target: ${TARGET_IP}:${TARGET_PORT}"
            echo ""
            echo -e "${YELLOW}Press Enter when attack is complete:${NC}"
            read -p ""
            ;;
        custom)
            bash "${SCRIPTS_DIR}/c2_beacon.sh" "${TARGET_IP}" "${TARGET_PORT}" "${ATTACK_RESULTS}" || SUCCESS="false"
            ;;
        manual)
            echo -e "${YELLOW}Manual attack - perform the attack in browser/tool${NC}"
            echo "Target: http://${TARGET_IP}:${TARGET_PORT}/"
            echo ""
            echo -e "${YELLOW}Press Enter when attack is complete:${NC}"
            read -p ""
            ;;
        *)
            echo -e "${RED}Unknown tool: ${TOOL}${NC}"
            SUCCESS="false"
            ;;
    esac
fi

# Record end time
TS_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo ""
echo -e "${BLUE}[${TS_END}] Attack complete${NC}"
echo ""

# Log the attack
log_attack "${ATTACK_ID}" "${TS_START}" "${TS_END}" "${CATEGORY}" "${SUBCATEGORY}" "${TECHNIQUE_ID}" "${TOOL}" "${TARGET_IP}" "${TARGET_PORT}" "${SERVICE}" "${SUCCESS}" "${NOTES}"

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ATTACK LOGGED                                                ║${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  ID:      ${ATTACK_ID}${NC}"
echo -e "${GREEN}║  Start:   ${TS_START}${NC}"
echo -e "${GREEN}║  End:     ${TS_END}${NC}"
echo -e "${GREEN}║  Success: ${SUCCESS}${NC}"
echo -e "${GREEN}║  Results: ${ATTACK_RESULTS}/${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Remember: Wait 2-5 minutes for Suricata to process before extracting ML data${NC}"
