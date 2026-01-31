#!/bin/bash
###############################################################################
# Nikto Scan Script
# Web vulnerability scanning against various targets with evasion variants
###############################################################################

SUBTYPE="${1:-dvwa}"
TARGET_IP="${2:-10.10.40.10}"
TARGET_PORT="${3:-80}"
RESULTS_DIR="${4:-.}"

mkdir -p "$RESULTS_DIR"

echo "[*] Nikto scanning: $SUBTYPE against ${TARGET_IP}:${TARGET_PORT}"

run_nikto_basic() {
    local ip="$1"
    local port="$2"
    local label="$3"

    echo "[*] Running basic Nikto scan against ${ip}:${port} (${label})"
    nikto -h "${ip}" -p "${port}" \
        -Format txt -output "${RESULTS_DIR}/nikto_${label}.txt" \
        -maxtime 300 \
        -Tuning 1234567890abc \
        2>&1 || true
}

run_nikto_evasion() {
    echo "[*] Running Nikto with IDS evasion techniques"

    # Evasion technique 1: Random URI encoding
    nikto -h "${TARGET_IP}" -p "${TARGET_PORT}" \
        -evasion 1 \
        -Format txt -output "${RESULTS_DIR}/nikto_evasion_1.txt" \
        -maxtime 180 \
        2>&1 || true
    sleep 5

    # Evasion technique 2: Directory self-reference
    nikto -h "${TARGET_IP}" -p "${TARGET_PORT}" \
        -evasion 2 \
        -Format txt -output "${RESULTS_DIR}/nikto_evasion_2.txt" \
        -maxtime 180 \
        2>&1 || true
    sleep 5

    # Evasion technique 4: Prepend long random string
    nikto -h "${TARGET_IP}" -p "${TARGET_PORT}" \
        -evasion 4 \
        -Format txt -output "${RESULTS_DIR}/nikto_evasion_4.txt" \
        -maxtime 180 \
        2>&1 || true
    sleep 5

    # Evasion technique 7: Random case sensitivity
    nikto -h "${TARGET_IP}" -p "${TARGET_PORT}" \
        -evasion 7 \
        -Format txt -output "${RESULTS_DIR}/nikto_evasion_7.txt" \
        -maxtime 180 \
        2>&1 || true

    echo "[+] Evasion scans complete"
}

# Source targets config for IPs
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

DVWA_IP="${DVWA_IP:-10.10.40.10}"
JUICE_IP="${JUICE_IP:-10.10.40.10}"
JUICE_PORT="${JUICE_PORT:-3000}"
WORDPRESS_IP="${WORDPRESS_IP:-10.10.40.30}"
WINDOWS_IP="${WINDOWS_IP:-10.10.40.21}"

case "$SUBTYPE" in
    dvwa)
        run_nikto_basic "$DVWA_IP" "80" "dvwa"
        ;;
    juice)
        run_nikto_basic "$JUICE_IP" "$JUICE_PORT" "juice_shop"
        ;;
    evasion)
        run_nikto_evasion
        ;;
    full)
        run_nikto_basic "$DVWA_IP" "80" "dvwa"
        sleep 10
        run_nikto_basic "$JUICE_IP" "$JUICE_PORT" "juice_shop"
        sleep 10
        run_nikto_evasion
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: dvwa, juice, evasion, full"
        exit 1
        ;;
esac

echo "[*] Nikto scan script complete"
