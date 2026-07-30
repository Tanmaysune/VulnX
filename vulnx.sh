#!/usr/bin/env bash
#
# ==============================================================================
#  VulnX — Website Reconnaissance & Vulnerability Assessment Tool
# ==============================================================================
#  Author  : Tanmay sune

#  DISCLAIMER:
#  This tool is for EDUCATIONAL and AUTHORIZED SECURITY TESTING purposes only.
#  Only scan targets you own or have explicit written permission to test.
#  Unauthorized scanning of systems may be illegal under laws such as the
#  IT Act 2000 (India), CFAA (USA), or equivalent legislation elsewhere.
# ==============================================================================

set -uo pipefail

# ------------------------------------------------------------------------------
# GLOBALS
# ------------------------------------------------------------------------------
VERSION="2.0.0"
TARGET=""
TARGET_HOST=""
PROTO="https"
OUTDIR="reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
TOP_PORTS=100
JSON_MODE=false
FINDINGS_TOTAL=0
FINDINGS_HIGH=0
FINDINGS_MED=0
FINDINGS_LOW=0
FINDINGS_INFO=0

# Available modules (id:label) — used for both CLI selection & web UI categories
ALL_MODULES="dns headers ssl files cms ports subdomains extra"
declare -A MODULE_LABEL=(
    [dns]="DNS & WHOIS Recon"
    [headers]="HTTP Security Headers"
    [ssl]="SSL/TLS Configuration"
    [files]="Sensitive File Disclosure"
    [cms]="CMS & Tech Fingerprinting"
    [ports]="Network Port Scan"
    [subdomains]="Subdomain Enumeration"
    [extra]="Real-World Exploit Surface Checks"
)
SELECTED_MODULES="$ALL_MODULES"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
ORANGE='\033[0;91m'; PURPLE='\033[0;95m'; TEAL='\033[0;96m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ------------------------------------------------------------------------------
# BANNER (multi-color, line by line)
# ------------------------------------------------------------------------------
banner() {
    local lines=(
				'__     __     _      __  __'
				'\ \   / /   _| |_ __ \ \/ /'
				' \ \ / / | | | | '"'"'_ \ \  / '
				'  \ V /| |_| | | | | |/  \ '
				'   \_/  \__,_|_|_| |_/_/\_\'
    )
    local colors=("$MAGENTA" "$PURPLE" "$BLUE" "$TEAL" "$CYAN")
    local i=0
    echo ""
    for line in "${lines[@]}"; do
        printf '%b' "${colors[$((i % ${#colors[@]}))]}"
        printf '%s' "$line"
        printf '%b\n' "${NC}"
        i=$((i+1))
    done
    echo -e "${BOLD}${ORANGE}Website Recon & Vulnerability Assessment Toolkit${NC}"
    echo -e "${DIM}${CYAN}          v${VERSION}${NC}\n"
}

# ------------------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------------------
log_info()    { $JSON_MODE || echo -e "${BLUE}[*]${NC} $1"; }
log_ok()      { $JSON_MODE || echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { $JSON_MODE || echo -e "${YELLOW}[!]${NC} $1"; }
log_bad()     { $JSON_MODE || echo -e "${RED}[-]${NC} $1"; }
section()     { $JSON_MODE || echo -e "\n${BOLD}${MAGENTA}==> $1${NC}"; }

# usage: finding <SEVERITY> <MODULE> "<title>" "<detail>"
finding() {
    local sev="$1" module="$2" title="$3" detail="$4"
    FINDINGS_TOTAL=$((FINDINGS_TOTAL+1))
    case "$sev" in
        HIGH) FINDINGS_HIGH=$((FINDINGS_HIGH+1)); local color="$RED" ;;
        MED)  FINDINGS_MED=$((FINDINGS_MED+1));   local color="$YELLOW" ;;
        LOW)  FINDINGS_LOW=$((FINDINGS_LOW+1));   local color="$CYAN" ;;
        *)    FINDINGS_INFO=$((FINDINGS_INFO+1)); local color="$BLUE"; sev="INFO" ;;
    esac
    $JSON_MODE || echo -e "  ${color}[${sev}]${NC} ${title} — ${detail}"
    printf "%s|%s|%s|%s\n" "$sev" "$module" "$title" "$detail" >> "$RAW_FINDINGS_FILE"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }
module_selected() { [[ " $SELECTED_MODULES " == *" $1 "* ]]; }

usage() {
cat << EOF
Usage: $0 -u <target_url> [options]

Required:
  -u, --url <url>          Target URL (e.g. https://example.com)

Options:
  -o, --outdir <dir>       Report output directory (default: ./reports)
  -p, --ports <n>          Number of top ports to scan (default: 100)
  -m, --modules <list>     Comma-separated modules to run (default: all)
                            Available: dns,headers,ssl,files,cms,ports,subdomains,extra
      --json                Machine-readable mode: suppress colored logs
  -h, --help                Show this help message

Example:
  $0 -u https://example.com
  $0 -u example.com -m headers,ssl,extra
EOF
exit 1
}

# ------------------------------------------------------------------------------
# ARGUMENT PARSING
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--url) TARGET="$2"; shift 2 ;;
        -o|--outdir) OUTDIR="$2"; shift 2 ;;
        -p|--ports) TOP_PORTS="$2"; shift 2 ;;
        -m|--modules) SELECTED_MODULES="$(echo "$2" | tr ',' ' ')"; shift 2 ;;
        --json) JSON_MODE=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$TARGET" ]] && usage

if [[ ! "$TARGET" =~ ^https?:// ]]; then
    TARGET="https://$TARGET"
fi
PROTO="$(echo "$TARGET" | sed -E 's#^(https?)://.*#\1#')"
TARGET_HOST="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*##; s#:.*##')"

mkdir -p "$OUTDIR"
REPORT_DIR="${OUTDIR}/${TARGET_HOST}_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"
RAW_FINDINGS_FILE="${REPORT_DIR}/findings.raw"
TXT_REPORT="${REPORT_DIR}/report.txt"
HTML_REPORT="${REPORT_DIR}/report.html"
JSON_REPORT="${REPORT_DIR}/report.json"
touch "$RAW_FINDINGS_FILE"

# ------------------------------------------------------------------------------
# MODULE: DNS & WHOIS RECON
# ------------------------------------------------------------------------------
module_dns_whois() {
    section "DNS & WHOIS Reconnaissance"
    if command_exists dig; then
        local ip ns_rec mx_rec
        ip=$(dig +short A "$TARGET_HOST" | head -n1)
        [[ -n "$ip" ]] && log_ok "Resolved IP: $ip" || log_warn "Could not resolve A record"
        ns_rec=$(dig +short NS "$TARGET_HOST")
        [[ -n "$ns_rec" ]] && log_info "Nameservers: $(echo "$ns_rec" | tr '\n' ' ')"
        mx_rec=$(dig +short MX "$TARGET_HOST")
        [[ -n "$mx_rec" ]] && log_info "MX records: $(echo "$mx_rec" | tr '\n' ' ')"
        if [[ -z "$(dig +short TXT "$TARGET_HOST" | grep -i spf)" ]]; then
            finding "LOW" "dns" "Missing SPF record" "No SPF TXT record found; domain may be spoofable for email"
        fi
        if [[ -z "$(dig +short TXT "$TARGET_HOST" | grep -i dmarc)" ]] && [[ -z "$(dig +short TXT "_dmarc.${TARGET_HOST}" | grep -i dmarc)" ]]; then
            finding "LOW" "dns" "Missing DMARC record" "No DMARC policy found; weakens anti-phishing posture for this domain"
        fi
    else
        log_warn "dig not installed — skipping DNS enumeration (install: apt install dnsutils)"
    fi
    if command_exists whois; then
        local reg exp
        reg=$(whois "$TARGET_HOST" 2>/dev/null | grep -i "Registrar:" | head -n1)
        exp=$(whois "$TARGET_HOST" 2>/dev/null | grep -iE "Expiry|Registry Expiry" | head -n1)
        [[ -n "$reg" ]] && log_info "$reg"
        [[ -n "$exp" ]] && log_info "$exp"
    else
        log_warn "whois not installed — skipping (install: apt install whois)"
    fi
}

# ------------------------------------------------------------------------------
# MODULE: HTTP SECURITY HEADERS
# ------------------------------------------------------------------------------
module_headers() {
    section "HTTP Security Header Analysis"
    local headers
    headers=$(curl -s -D - -o /dev/null -L --max-time 15 -A "VulnX/${VERSION}" "$TARGET")
    if [[ -z "$headers" ]]; then
        log_bad "No response received from target — is it reachable?"
        return
    fi
    echo "$headers" > "${REPORT_DIR}/raw_headers.txt"

    check_header() {
        local name="$1" sev="$2" desc="$3"
        if ! echo "$headers" | grep -qi "^$name:"; then
            finding "$sev" "headers" "Missing $name" "$desc"
        else
            log_ok "$name present"
        fi
    }
    check_header "Strict-Transport-Security" "MED" "HSTS not enforced; site vulnerable to SSL-stripping/downgrade attacks"
    check_header "Content-Security-Policy" "MED" "No CSP; increases risk/impact of XSS attacks"
    check_header "X-Frame-Options" "LOW" "Site may be vulnerable to clickjacking"
    check_header "X-Content-Type-Options" "LOW" "MIME-sniffing not disabled; risk of content-type attacks"
    check_header "Referrer-Policy" "LOW" "No referrer policy; may leak URLs to third parties"
    check_header "Permissions-Policy" "LOW" "No Permissions-Policy; browser features not restricted"

    local server_hdr powered_by
    server_hdr=$(echo "$headers" | grep -i "^Server:" | head -n1 | cut -d' ' -f2- | tr -d '\r')
    powered_by=$(echo "$headers" | grep -i "^X-Powered-By:" | head -n1 | cut -d' ' -f2- | tr -d '\r')
    [[ -n "$server_hdr" ]] && finding "INFO" "headers" "Server header disclosed" "Server: $server_hdr"
    [[ -n "$powered_by" ]] && finding "LOW" "headers" "X-Powered-By header disclosed" "Reveals backend technology: $powered_by"

    local cookies
    cookies=$(echo "$headers" | grep -i "^Set-Cookie:")
    if [[ -n "$cookies" ]]; then
        echo "$cookies" | grep -qi "secure" || finding "MED" "headers" "Cookie missing Secure flag" "Session cookies may be sent over unencrypted channels"
        echo "$cookies" | grep -qi "httponly" || finding "MED" "headers" "Cookie missing HttpOnly flag" "Cookies accessible via JavaScript — raises XSS impact"
        echo "$cookies" | grep -qi "samesite" || finding "LOW" "headers" "Cookie missing SameSite attribute" "Increases CSRF risk"
    fi
}

# ------------------------------------------------------------------------------
# MODULE: SSL/TLS CHECK
# ------------------------------------------------------------------------------
module_ssl() {
    section "SSL/TLS Configuration Check"
    if [[ "$PROTO" != "https" ]]; then
        finding "HIGH" "ssl" "Site not served over HTTPS" "Target uses plain HTTP; all traffic is unencrypted"
        return
    fi
    if ! command_exists openssl; then
        log_warn "openssl not installed — skipping TLS checks"
        return
    fi
    local cert_info exp_date days_left
    cert_info=$(echo | openssl s_client -servername "$TARGET_HOST" -connect "${TARGET_HOST}:443" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
    if [[ -z "$cert_info" ]]; then
        finding "HIGH" "ssl" "Could not retrieve SSL certificate" "TLS handshake failed on port 443"
        return
    fi
    echo "$cert_info" > "${REPORT_DIR}/ssl_cert.txt"
    exp_date=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2)
    if [[ -n "$exp_date" ]]; then
        local exp_epoch now_epoch
        exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null)
        now_epoch=$(date +%s)
        if [[ -n "$exp_epoch" ]]; then
            days_left=$(( (exp_epoch - now_epoch) / 86400 ))
            if [[ $days_left -lt 0 ]]; then
                finding "HIGH" "ssl" "SSL certificate expired" "Certificate expired on $exp_date"
            elif [[ $days_left -lt 15 ]]; then
                finding "MED" "ssl" "SSL certificate expiring soon" "Expires in $days_left days ($exp_date)"
            else
                log_ok "Certificate valid, expires in $days_left days"
            fi
        fi
    fi
    for proto_flag in ssl2 ssl3 tls1 tls1_1; do
        if openssl s_client -"$proto_flag" -connect "${TARGET_HOST}:443" </dev/null >/dev/null 2>&1; then
            finding "HIGH" "ssl" "Weak TLS/SSL protocol supported" "Server accepts deprecated protocol: $proto_flag"
        fi
    done
}

# ------------------------------------------------------------------------------
# MODULE: SENSITIVE FILE & PATH DISCLOSURE
# ------------------------------------------------------------------------------
module_sensitive_files() {
    section "Sensitive File & Path Disclosure Check"
    local paths=(
        "/.git/config" "/.env" "/.env.production" "/wp-config.php.bak" "/config.php.bak"
        "/backup.zip" "/backup.sql" "/.htaccess" "/.DS_Store" "/phpinfo.php" "/server-status"
        "/.well-known/security.txt" "/robots.txt" "/sitemap.xml" "/admin" "/administrator"
        "/wp-admin" "/.svn/entries"
    )
    for path in "${paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 -A "VulnX/${VERSION}" "${TARGET}${path}")
        if [[ "$code" == "200" ]]; then
            case "$path" in
                "/robots.txt"|"/sitemap.xml"|"/.well-known/security.txt") log_info "$path found (HTTP 200)" ;;
                "/admin"|"/administrator"|"/wp-admin") finding "INFO" "files" "Admin panel exposed" "$path is reachable (HTTP 200) — ensure it's protected" ;;
                *) finding "HIGH" "files" "Sensitive file exposed" "$path returned HTTP 200 — potential data leak" ;;
            esac
        fi
    done
}

# ------------------------------------------------------------------------------
# MODULE: CMS / TECHNOLOGY FINGERPRINTING
# ------------------------------------------------------------------------------
module_cms_detect() {
    section "CMS & Technology Fingerprinting"
    local body
    body=$(curl -s -L --max-time 15 -A "VulnX/${VERSION}" "$TARGET")
    echo "$body" > "${REPORT_DIR}/page_body.html"
    if echo "$body" | grep -qi "wp-content\|wp-includes"; then
        log_ok "Detected CMS: WordPress"
        finding "INFO" "cms" "CMS Detected" "WordPress — check for outdated plugins/themes and enumerate via wpscan"
    elif echo "$body" | grep -qi "Joomla"; then
        log_ok "Detected CMS: Joomla"
        finding "INFO" "cms" "CMS Detected" "Joomla — verify version against known CVEs"
    elif echo "$body" | grep -qi "Drupal"; then
        log_ok "Detected CMS: Drupal"
        finding "INFO" "cms" "CMS Detected" "Drupal — verify version against known CVEs"
    else
        log_info "No common CMS signature detected"
    fi
    if echo "$body" | grep -qi "jquery"; then
        local jq_ver
        jq_ver=$(echo "$body" | grep -oE "jquery[/-][0-9]+\.[0-9]+\.[0-9]+" | head -n1)
        [[ -n "$jq_ver" ]] && log_info "Detected library: $jq_ver"
    fi
}

# ------------------------------------------------------------------------------
# MODULE: PORT SCAN (nmap)
# ------------------------------------------------------------------------------
module_portscan() {
    section "Network Port Scan"
    if ! command_exists nmap; then
        log_warn "nmap not installed — skipping port scan (install: apt install nmap)"
        return
    fi
    log_info "Scanning top $TOP_PORTS ports on $TARGET_HOST (this may take a moment)..."
    local scan_out="${REPORT_DIR}/nmap_scan.txt"
    nmap -Pn --top-ports "$TOP_PORTS" -sV --open "$TARGET_HOST" -oN "$scan_out" >/dev/null 2>&1
    if [[ -f "$scan_out" ]]; then
        grep -E "^[0-9]+/tcp" "$scan_out" | while read -r line; do log_info "Open port: $line"; done
        grep -qi "21/tcp.*open" "$scan_out" && finding "MED" "ports" "FTP port open" "Port 21 open — FTP often allows anonymous/weak auth"
        grep -qi "3389/tcp.*open" "$scan_out" && finding "HIGH" "ports" "RDP port open to internet" "Port 3389 exposed — high risk of brute-force/exploits"
        grep -qi "23/tcp.*open" "$scan_out" && finding "HIGH" "ports" "Telnet port open" "Port 23 open — unencrypted remote access protocol"
        grep -qi "3306/tcp.*open" "$scan_out" && finding "HIGH" "ports" "MySQL port exposed" "Port 3306 open to the internet — database should not be public"
        grep -qi "6379/tcp.*open" "$scan_out" && finding "HIGH" "ports" "Redis port exposed" "Port 6379 open — Redis often has no auth by default"
        grep -qi "27017/tcp.*open" "$scan_out" && finding "HIGH" "ports" "MongoDB port exposed" "Port 27017 open to the internet"
    fi
}

# ------------------------------------------------------------------------------
# MODULE: SUBDOMAIN ENUMERATION (crt.sh)
# ------------------------------------------------------------------------------
module_subdomains() {
    section "Subdomain Enumeration (Certificate Transparency)"
    local result
    result=$(curl -s --max-time 20 "https://crt.sh/?q=%25.${TARGET_HOST}&output=json" 2>/dev/null)
    if [[ -z "$result" || "$result" == "[]" ]]; then
        log_warn "No subdomain data returned (crt.sh may be rate-limiting or unreachable)"
        return
    fi
    local subs count
    subs=$(echo "$result" | grep -oE '"name_value":"[^"]*"' | sed -E 's/"name_value":"//; s/"$//' | tr ',' '\n' | sort -u | grep -v '\*')
    count=$(echo "$subs" | grep -c .)
    echo "$subs" > "${REPORT_DIR}/subdomains.txt"
    log_ok "Found $count unique subdomain(s) — saved to subdomains.txt"
    finding "INFO" "subdomains" "Subdomains enumerated" "$count subdomains discovered via certificate transparency logs"
}

# ------------------------------------------------------------------------------
# MODULE: REAL-WORLD EXPLOIT-SURFACE CHECKS (extra)
# ------------------------------------------------------------------------------
module_extra_checks() {
    section "Real-World Exploit Surface Checks"

    # 1. CORS misconfiguration — reflect a bogus Origin and see if it's echoed back with credentials allowed
    local cors_hdrs
    cors_hdrs=$(curl -s -D - -o /dev/null --max-time 10 -H "Origin: https://evil-attacker-test.example" -A "VulnX/${VERSION}" "$TARGET")
    if echo "$cors_hdrs" | grep -qi "Access-Control-Allow-Origin: https://evil-attacker-test.example"; then
        if echo "$cors_hdrs" | grep -qi "Access-Control-Allow-Credentials: true"; then
            finding "HIGH" "extra" "CORS misconfiguration (credentialed)" "Server reflects arbitrary Origin AND allows credentials — cross-origin data theft is possible"
        else
            finding "MED" "extra" "CORS reflects arbitrary Origin" "Server echoes any Origin header back in Access-Control-Allow-Origin"
        fi
    elif echo "$cors_hdrs" | grep -qi "Access-Control-Allow-Origin: \*"; then
        finding "LOW" "extra" "CORS allows all origins (*)" "Wildcard CORS policy — acceptable only for fully public APIs"
    else
        log_ok "No obvious CORS misconfiguration detected"
    fi

    # 2. Dangerous HTTP methods (TRACE / PUT / DELETE)
    local allow_hdr
    allow_hdr=$(curl -s -X OPTIONS -D - -o /dev/null --max-time 10 -A "VulnX/${VERSION}" "$TARGET" | grep -i "^Allow:")
    if [[ -n "$allow_hdr" ]]; then
        log_info "$allow_hdr"
        echo "$allow_hdr" | grep -qi "TRACE" && finding "MED" "extra" "TRACE method enabled" "Vulnerable to Cross-Site Tracing (XST) attacks; disable TRACE"
        echo "$allow_hdr" | grep -qi "PUT" && finding "MED" "extra" "PUT method enabled" "May allow unauthorized file upload if not properly access-controlled"
        echo "$allow_hdr" | grep -qi "DELETE" && finding "MED" "extra" "DELETE method enabled" "May allow unauthorized resource deletion if not properly access-controlled"
    fi

    # 3. Open redirect (passive — checks common query params reflected into Location header)
    local redirect_params=("redirect" "url" "next" "return" "dest" "continue")
    for param in "${redirect_params[@]}"; do
        local loc
        loc=$(curl -s -D - -o /dev/null --max-time 8 -A "VulnX/${VERSION}" "${TARGET}/?${param}=https://evil-attacker-test.example" | grep -i "^Location:")
        if echo "$loc" | grep -qi "evil-attacker-test.example"; then
            finding "MED" "extra" "Possible open redirect" "Parameter '${param}' reflects external URLs into the Location header unvalidated"
            break
        fi
    done

    # 4. Mixed content (HTTP resources referenced from an HTTPS page)
    if [[ "$PROTO" == "https" ]]; then
        local body mixed_count
        body=$(curl -s -L --max-time 15 -A "VulnX/${VERSION}" "$TARGET")
        mixed_count=$(echo "$body" | grep -oE '(src|href)=["'"'"']http://[^"'"'"']+' | grep -v "http://localhost" | wc -l)
        if [[ "$mixed_count" -gt 0 ]]; then
            finding "LOW" "extra" "Mixed content detected" "$mixed_count resource(s) loaded over plain HTTP on an HTTPS page"
        fi
    fi

    # 5. Directory listing enabled
    local listing_check
    listing_check=$(curl -s --max-time 8 -A "VulnX/${VERSION}" "${TARGET}/uploads/" 2>/dev/null)
    if echo "$listing_check" | grep -qi "Index of /"; then
        finding "MED" "extra" "Directory listing enabled" "/uploads/ (and possibly other directories) expose full file listings"
    fi

    # 6. Exposed email addresses in page source (info leak / phishing target surface)
    local body2 emails email_count
    body2=$(cat "${REPORT_DIR}/page_body.html" 2>/dev/null || curl -s -L --max-time 15 -A "VulnX/${VERSION}" "$TARGET")
    emails=$(echo "$body2" | grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | sort -u)
    email_count=$(echo "$emails" | grep -c . || true)
    if [[ "$email_count" -gt 0 ]]; then
        finding "INFO" "extra" "Email addresses exposed in page source" "$email_count unique address(es) found — potential phishing/spam target list"
        echo "$emails" > "${REPORT_DIR}/exposed_emails.txt"
    fi

    # 7. robots.txt disallowed paths — check if any are actually publicly reachable anyway
    local robots disallowed
    robots=$(curl -s --max-time 8 -A "VulnX/${VERSION}" "${TARGET}/robots.txt")
    if [[ -n "$robots" ]]; then
        disallowed=$(echo "$robots" | grep -i "^Disallow:" | awk '{print $2}' | grep -v '^$' | head -n 10)
        local leaked=0
        while read -r path; do
            [[ -z "$path" ]] && continue
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 -A "VulnX/${VERSION}" "${TARGET}${path}")
            if [[ "$code" == "200" ]]; then
                leaked=$((leaked+1))
            fi
        done <<< "$disallowed"
        if [[ "$leaked" -gt 0 ]]; then
            finding "MED" "extra" "robots.txt Disallow paths publicly reachable" "$leaked path(s) that robots.txt tries to hide from search engines are directly accessible — this is not access control"
        fi
    fi

    # 8. WAF / CDN detection (informational — helps interpret other results)
    local waf_hdrs waf_detected=""
    waf_hdrs=$(curl -s -D - -o /dev/null --max-time 10 -A "VulnX/${VERSION}" "$TARGET")
    if echo "$waf_hdrs" | grep -qi "cf-ray\|cloudflare"; then waf_detected="Cloudflare"; fi
    if echo "$waf_hdrs" | grep -qi "x-sucuri-id"; then waf_detected="Sucuri"; fi
    if echo "$waf_hdrs" | grep -qi "x-akamai"; then waf_detected="Akamai"; fi
    if echo "$waf_hdrs" | grep -qi "server: awselb\|x-amz-cf-id"; then waf_detected="AWS (ELB/CloudFront)"; fi
    if [[ -n "$waf_detected" ]]; then
        log_ok "WAF/CDN detected: $waf_detected"
        finding "INFO" "extra" "WAF/CDN detected" "$waf_detected — active scan results may be filtered/rate-limited by this layer"
    fi
}

# ------------------------------------------------------------------------------
# REPORT GENERATION
# ------------------------------------------------------------------------------
generate_txt_report() {
    {
        echo "==================================================================="
        echo " VulnX Report"
        echo " Target      : $TARGET"
        echo " Scan Date   : $(date)"
        echo " Modules Run : $SELECTED_MODULES"
        echo "==================================================================="
        echo ""
        echo "SUMMARY"
        echo "-------"
        echo "Total Findings : $FINDINGS_TOTAL"
        echo "  HIGH         : $FINDINGS_HIGH"
        echo "  MEDIUM       : $FINDINGS_MED"
        echo "  LOW          : $FINDINGS_LOW"
        echo "  INFO         : $FINDINGS_INFO"
        echo ""
        echo "DETAILED FINDINGS"
        echo "-----------------"
        while IFS='|' read -r sev module title detail; do
            printf "[%-4s] (%s) %s\n        %s\n\n" "$sev" "$module" "$title" "$detail"
        done < "$RAW_FINDINGS_FILE"
    } > "$TXT_REPORT"
}

generate_html_report() {
    local rows=""
    while IFS='|' read -r sev module title detail; do
        local badge_color="#3498db"
        case "$sev" in
            HIGH) badge_color="#e74c3c" ;;
            MED)  badge_color="#f39c12" ;;
            LOW)  badge_color="#3498db" ;;
            INFO) badge_color="#95a5a6" ;;
        esac
        rows+="<tr><td><span class='badge' style='background:${badge_color}'>${sev}</span></td><td>${module}</td><td>${title}</td><td>${detail}</td></tr>"
    done < "$RAW_FINDINGS_FILE"

cat > "$HTML_REPORT" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnX Report — ${TARGET_HOST}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:2rem; }
  .container { max-width: 1000px; margin: auto; }
  h1 { color:#fff; margin-bottom:0.2rem; }
  .meta { color:#9aa0a6; margin-bottom:2rem; }
  .summary { display:flex; gap:1rem; margin-bottom:2rem; flex-wrap:wrap; }
  .card { background:#1a1d24; border-radius:10px; padding:1rem 1.5rem; flex:1; min-width:120px; text-align:center; border:1px solid #2a2e37; }
  .card h2 { margin:0; font-size:2rem; }
  .card p { margin:0.2rem 0 0; color:#9aa0a6; font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em; }
  table { width:100%; border-collapse: collapse; background:#1a1d24; border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:0.8rem 1rem; border-bottom:1px solid #2a2e37; font-size:0.9rem; }
  th { background:#20242c; color:#9aa0a6; text-transform:uppercase; font-size:0.75rem; letter-spacing:0.05em; }
  .badge { color:#fff; padding:0.25rem 0.6rem; border-radius:20px; font-size:0.7rem; font-weight:bold; }
  footer { margin-top:2rem; color:#666; font-size:0.8rem; text-align:center; }
</style>
</head>
<body>
<div class="container">
  <h1>VulnX Report</h1>
  <div class="meta">Target: <b>${TARGET}</b> &nbsp;|&nbsp; Scanned: $(date)</div>
  <div class="summary">
    <div class="card"><h2>${FINDINGS_TOTAL}</h2><p>Total</p></div>
    <div class="card" style="color:#e74c3c"><h2>${FINDINGS_HIGH}</h2><p>High</p></div>
    <div class="card" style="color:#f39c12"><h2>${FINDINGS_MED}</h2><p>Medium</p></div>
    <div class="card" style="color:#3498db"><h2>${FINDINGS_LOW}</h2><p>Low</p></div>
    <div class="card" style="color:#95a5a6"><h2>${FINDINGS_INFO}</h2><p>Info</p></div>
  </div>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th></tr>
    ${rows}
  </table>
  <footer>Generated by VulnX v${VERSION} — For authorized security testing only.</footer>
</div>
</body>
</html>
HTMLEOF
}

generate_json_report() {
    local findings_json="[]"
    if [[ -s "$RAW_FINDINGS_FILE" ]]; then
        findings_json=$(python3 - "$RAW_FINDINGS_FILE" << 'PYEOF'
import json, sys
items = []
with open(sys.argv[1]) as f:
    for line in f:
        parts = line.rstrip("\n").split("|", 3)
        if len(parts) == 4:
            items.append({"severity": parts[0], "module": parts[1], "title": parts[2], "detail": parts[3]})
print(json.dumps(items))
PYEOF
) 2>/dev/null || findings_json="[]"
    fi

    python3 - "$JSON_REPORT" "$TARGET" "$FINDINGS_TOTAL" "$FINDINGS_HIGH" "$FINDINGS_MED" "$FINDINGS_LOW" "$FINDINGS_INFO" "$findings_json" << 'PYEOF' 2>/dev/null
import json, sys, datetime
out, target, total, high, med, low, info, findings_json = sys.argv[1:9]
data = {
    "target": target,
    "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
    "summary": {"total": int(total), "high": int(high), "medium": int(med), "low": int(low), "info": int(info)},
    "findings": json.loads(findings_json),
}
with open(out, "w") as f:
    json.dump(data, f, indent=2)
PYEOF
}

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------
main() {
    banner
    log_info "Target: $TARGET"
    log_info "Report directory: $REPORT_DIR"
    log_info "Modules: $SELECTED_MODULES"
    $JSON_MODE || echo -e "${YELLOW}[!] Ensure you have authorization to scan this target.${NC}\n"

    module_selected dns         && module_dns_whois
    module_selected headers     && module_headers
    module_selected ssl         && module_ssl
    module_selected files       && module_sensitive_files
    module_selected cms         && module_cms_detect
    module_selected ports       && module_portscan
    module_selected subdomains  && module_subdomains
    module_selected extra       && module_extra_checks

    generate_txt_report
    generate_html_report
    generate_json_report

    section "Scan Complete"
    if ! $JSON_MODE; then
        echo -e "Total Findings : ${BOLD}${FINDINGS_TOTAL}${NC}"
        echo -e "  ${RED}HIGH:   $FINDINGS_HIGH${NC}"
        echo -e "  ${YELLOW}MEDIUM: $FINDINGS_MED${NC}"
        echo -e "  ${CYAN}LOW:    $FINDINGS_LOW${NC}"
        echo -e "  ${BLUE}INFO:   $FINDINGS_INFO${NC}"
        echo ""
        log_ok "Text report: $TXT_REPORT"
        log_ok "HTML report: $HTML_REPORT"
        log_ok "JSON report: $JSON_REPORT"
    fi
    echo "$JSON_REPORT"
}

main
