#!/bin/bash
###############################################################################
# Reconnaissance - Port Scanning with Nmap
# Various scan types for different detection signatures
###############################################################################

TARGET="${1:-10.10.40.0/24}"
TARGET_PORT="${2:-*}"  # Not used for most scans
RESULTS_DIR="${3:-.}"

echo "=============================================="
echo "Nmap Reconnaissance Suite"
echo "Target: ${TARGET}"
echo "=============================================="
echo ""

echo "Select scan type:"
echo "1) SYN scan (fast, common, -sS)"
echo "2) TCP Connect scan (noisy, -sT)"
echo "3) UDP scan (slow, -sU)"
echo "4) Version detection (-sV)"
echo "5) OS fingerprinting (-O)"
echo "6) Aggressive scan (-A)"
echo "7) Stealth scan (slow, -sS -T2)"
echo "8) Full port scan (all 65535)"
echo "9) Quick service scan (top 100)"
echo ""
read -p "Choice [1-9]: " choice

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

case "$choice" in
    1)
        echo "Running SYN scan..."
        sudo nmap -sS -T4 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_syn_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_syn_${TIMESTAMP}.xml"
        ;;
    2)
        echo "Running TCP Connect scan..."
        nmap -sT -T4 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_connect_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_connect_${TIMESTAMP}.xml"
        ;;
    3)
        echo "Running UDP scan (this will take a while)..."
        sudo nmap -sU -T4 --top-ports 100 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_udp_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_udp_${TIMESTAMP}.xml"
        ;;
    4)
        echo "Running Version detection scan..."
        sudo nmap -sV -T4 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_version_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_version_${TIMESTAMP}.xml"
        ;;
    5)
        echo "Running OS fingerprinting..."
        sudo nmap -O -T4 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_os_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_os_${TIMESTAMP}.xml"
        ;;
    6)
        echo "Running Aggressive scan (-A)..."
        sudo nmap -A -T4 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_aggressive_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_aggressive_${TIMESTAMP}.xml"
        ;;
    7)
        echo "Running Stealth scan (slow)..."
        sudo nmap -sS -T2 -Pn -f "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_stealth_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_stealth_${TIMESTAMP}.xml"
        ;;
    8)
        echo "Running Full port scan (this will take a LONG time)..."
        sudo nmap -sS -T4 -p- -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_fullport_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_fullport_${TIMESTAMP}.xml"
        ;;
    9)
        echo "Running Quick service scan..."
        sudo nmap -sS -sV -T4 --top-ports 100 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_quick_${TIMESTAMP}.txt" \
            -oX "${RESULTS_DIR}/nmap_quick_${TIMESTAMP}.xml"
        ;;
    *)
        echo "Invalid choice, running default SYN scan..."
        sudo nmap -sS -T4 -Pn "${TARGET}" \
            -oN "${RESULTS_DIR}/nmap_default_${TIMESTAMP}.txt"
        ;;
esac

echo ""
echo "Scan complete. Results saved to ${RESULTS_DIR}/"
