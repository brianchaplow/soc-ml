#!/bin/bash
###############################################################################
# Directory Enumeration / Web Fuzzing
# Tools: gobuster, dirb, ffuf
###############################################################################

TARGET_IP="${1:-10.10.40.10}"
TARGET_PORT="${2:-80}"
RESULTS_DIR="${3:-.}"

source "$(dirname "$0")/../configs/wordlists.conf" 2>/dev/null || true

echo "=============================================="
echo "Directory Enumeration Suite"
echo "Target: http://${TARGET_IP}:${TARGET_PORT}"
echo "=============================================="
echo ""

# Default wordlist
WORDLIST="${DIRB_COMMON:-/usr/share/wordlists/dirb/common.txt}"

echo "Select enumeration tool:"
echo "1) Gobuster (fast, recommended)"
echo "2) Dirb (classic)"
echo "3) Aggressive gobuster (bigger wordlist)"
echo "4) File extension scan (.php, .txt, .bak)"
echo ""
read -p "Choice [1-4]: " choice

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}"

case "$choice" in
    1)
        echo "Running Gobuster with common wordlist..."
        gobuster dir \
            -u "${TARGET_URL}" \
            -w "${WORDLIST}" \
            -t 20 \
            -o "${RESULTS_DIR}/gobuster_${TIMESTAMP}.txt" \
            --no-error
        ;;
    2)
        echo "Running Dirb..."
        dirb "${TARGET_URL}" "${WORDLIST}" \
            -o "${RESULTS_DIR}/dirb_${TIMESTAMP}.txt" \
            -S  # Silent, don't show tested words
        ;;
    3)
        echo "Running Aggressive Gobuster (medium wordlist)..."
        BIG_WORDLIST="${DIRBUSTER_MEDIUM:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}"
        if [[ -f "${BIG_WORDLIST}" ]]; then
            gobuster dir \
                -u "${TARGET_URL}" \
                -w "${BIG_WORDLIST}" \
                -t 30 \
                -o "${RESULTS_DIR}/gobuster_aggressive_${TIMESTAMP}.txt" \
                --no-error
        else
            echo "Medium wordlist not found, using common..."
            gobuster dir \
                -u "${TARGET_URL}" \
                -w "${WORDLIST}" \
                -t 30 \
                -o "${RESULTS_DIR}/gobuster_aggressive_${TIMESTAMP}.txt" \
                --no-error
        fi
        ;;
    4)
        echo "Running file extension scan..."
        gobuster dir \
            -u "${TARGET_URL}" \
            -w "${WORDLIST}" \
            -x php,txt,bak,old,html,htm,asp,aspx,jsp,sql,db,config,inc \
            -t 20 \
            -o "${RESULTS_DIR}/gobuster_ext_${TIMESTAMP}.txt" \
            --no-error
        ;;
    *)
        echo "Invalid choice, running default gobuster..."
        gobuster dir \
            -u "${TARGET_URL}" \
            -w "${WORDLIST}" \
            -t 20 \
            -o "${RESULTS_DIR}/gobuster_default_${TIMESTAMP}.txt" \
            --no-error
        ;;
esac

echo ""
echo "Directory enumeration complete. Results saved to ${RESULTS_DIR}/"
