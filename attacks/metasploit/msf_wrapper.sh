#!/bin/bash
###############################################################################
# Metasploit Wrapper Script
# Bridge between campaign runner and msfconsole resource files
#
# Usage: ./msf_wrapper.sh <rc_file> <target_ip> <target_port> <results_dir>
#
# Substitutes TARGET_IP, TARGET_PORT, LHOST in .rc files, runs msfconsole,
# captures output, and parses results.
###############################################################################

set -euo pipefail

RC_FILE="${1:?Usage: msf_wrapper.sh <rc_file> <target_ip> <target_port> <results_dir>}"
TARGET_IP="${2:?Target IP required}"
TARGET_PORT="${3:?Target port required}"
RESULTS_DIR="${4:-.}"

# Source IP for reverse connections
LHOST="10.10.20.20"

# Timeout for msfconsole (seconds)
MSF_TIMEOUT="${MSF_TIMEOUT:-300}"

mkdir -p "$RESULTS_DIR"

echo "[*] Metasploit wrapper"
echo "[*] RC file:     $RC_FILE"
echo "[*] Target:      ${TARGET_IP}:${TARGET_PORT}"
echo "[*] Results:     $RESULTS_DIR"

###############################################################################
# Validate
###############################################################################

if [[ ! -f "$RC_FILE" ]]; then
    echo "[!] RC file not found: $RC_FILE"
    exit 1
fi

if ! command -v msfconsole &>/dev/null; then
    echo "[!] msfconsole not found. Is Metasploit installed?"
    echo "[*] Falling back to nmap-based scan..."

    # Fallback: run nmap service scan against the port
    nmap -sV -p "$TARGET_PORT" "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_fallback.txt" 2>&1 || true
    exit 0
fi

###############################################################################
# Prepare RC file with variable substitution
###############################################################################

TEMP_RC=$(mktemp /tmp/msf_XXXXXX.rc)

# Substitute variables in RC file
sed -e "s|%%TARGET_IP%%|${TARGET_IP}|g" \
    -e "s|%%TARGET_PORT%%|${TARGET_PORT}|g" \
    -e "s|%%LHOST%%|${LHOST}|g" \
    -e "s|%%RESULTS_DIR%%|${RESULTS_DIR}|g" \
    "$RC_FILE" > "$TEMP_RC"

# Append exit command to ensure msfconsole exits
echo "" >> "$TEMP_RC"
echo "exit" >> "$TEMP_RC"

echo "[*] Prepared RC file:"
cat "$TEMP_RC" | head -20

###############################################################################
# Execute
###############################################################################

MSF_OUTPUT="${RESULTS_DIR}/msf_output.txt"

echo "[*] Running msfconsole (timeout: ${MSF_TIMEOUT}s)..."

timeout "$MSF_TIMEOUT" msfconsole -q -r "$TEMP_RC" 2>&1 | tee "$MSF_OUTPUT" || {
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
        echo "[!] msfconsole timed out after ${MSF_TIMEOUT}s"
    else
        echo "[!] msfconsole exited with code $exit_code"
    fi
}

###############################################################################
# Parse Results
###############################################################################

echo ""
echo "[*] Parsing results..."

# Check for successful exploitation
if grep -qi "session.*opened\|command shell session\|meterpreter.*session\|login.*success" "$MSF_OUTPUT" 2>/dev/null; then
    echo "[+] EXPLOITATION SUCCESSFUL — session or credentials found"
    echo "SUCCESS" > "${RESULTS_DIR}/msf_status.txt"
elif grep -qi "auxiliary.*module.*execution completed\|scanner.*completed" "$MSF_OUTPUT" 2>/dev/null; then
    echo "[*] Module execution completed"
    echo "COMPLETED" > "${RESULTS_DIR}/msf_status.txt"
elif grep -qi "exploit completed.*no session\|no results" "$MSF_OUTPUT" 2>/dev/null; then
    echo "[-] Exploit completed but no session obtained"
    echo "NO_SESSION" > "${RESULTS_DIR}/msf_status.txt"
else
    echo "[*] Module finished (check output for details)"
    echo "UNKNOWN" > "${RESULTS_DIR}/msf_status.txt"
fi

# Extract found credentials
grep -i "login\|password\|credential\|success" "$MSF_OUTPUT" 2>/dev/null \
    > "${RESULTS_DIR}/msf_credentials.txt" || true

###############################################################################
# Cleanup
###############################################################################

rm -f "$TEMP_RC"

echo "[*] Metasploit wrapper complete"
echo "[*] Output: ${MSF_OUTPUT}"
