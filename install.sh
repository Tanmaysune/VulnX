#!/usr/bin/env bash
# install.sh — checks & installs dependencies for VulnX (Debian/Ubuntu/Kali)

set -e

echo "Checking dependencies for VulnX..."

DEPS=(curl openssl dig whois nmap)
MISSING=()

for dep in "${DEPS[@]}"; do
    bin="$dep"
    [[ "$dep" == "dig" ]] && bin="dig"
    if ! command -v "$bin" >/dev/null 2>&1; then
        MISSING+=("$dep")
    fi
done

if [[ ${#MISSING[@]} -eq 0 ]]; then
    echo "✅ All dependencies already installed."
    exit 0
fi

echo "Missing: ${MISSING[*]}"
echo "Installing via apt (requires sudo)..."

sudo apt update
# map friendly names to actual apt packages
for dep in "${MISSING[@]}"; do
    case "$dep" in
        dig) sudo apt install -y dnsutils ;;
        *)   sudo apt install -y "$dep" ;;
    esac
done

echo "✅ Setup complete. Run: ./vulnscan.sh -u https://your-target.com"
