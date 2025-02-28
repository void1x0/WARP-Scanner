#!/bin/bash
# Check for minimum Bash version (4+ is required for associative arrays)
if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "Error: Bash version 4 or higher is required." >&2
    exit 1
fi

# ----- Error Handling & Prerequisite Checks -----

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

# Check for required commands: bc and dig
for cmd in bc dig; do
    if ! command -v "$cmd" >/dev/null; then
        error_exit "Required command '$cmd' not found. Please install it."
    fi
done

# Check for timeout command. On macOS, if not found, try using gtimeout (from coreutils).
if ! command -v timeout >/dev/null; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v gtimeout >/dev/null; then
            alias timeout=gtimeout
        else
            error_exit "timeout command not found. On macOS, please install coreutils (e.g., via Homebrew) for gtimeout."
        fi
    else
        error_exit "timeout command not found. Please install it."
    fi
fi

# ----- Setting Variables and Constants -----

# Colors (enabled if terminal supports color)
if [ -t 1 ]; then
    red='\033[38;5;196m'
    green='\033[38;5;82m'
    yellow='\033[38;5;208m'
    blue='\033[38;5;27m'
    magenta='\033[38;5;201m'
    cyan='\033[38;5;117m'
    reset='\033[0m'
else
    red=''
    green=''
    yellow=''
    blue=''
    magenta=''
    cyan=''
    reset=''
fi

VERSION="1.2"

# Set temporary and output file paths based on platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    DEFAULT_CONFIG_PATH="$HOME/wg-config.conf"
    TEMP_DIR="/tmp/warp-scanner"
elif [[ "$OSTYPE" == "linux-android"* || -d "/storage/emulated/0" ]]; then
    DEFAULT_CONFIG_PATH="/storage/emulated/0/wg-config.conf"
    TEMP_DIR="$HOME/warp-scanner-tmp"
else
    DEFAULT_CONFIG_PATH="$HOME/wg-config.conf"
    TEMP_DIR="/tmp/warp-scanner"
fi

# Create temporary directory
mkdir -p "$TEMP_DIR"
IP_FILE="$TEMP_DIR/ip.txt"
RESULT_FILE="$TEMP_DIR/result.txt"
BEST_IPS_FILE="$TEMP_DIR/clean_ips_final.txt"

# Determine system architecture for downloading the appropriate warpendpoint
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ENDPOINT_ARCH="amd64"
        ;;
    aarch64|arm64)
        ENDPOINT_ARCH="arm64"
        ;;
    arm*)
        ENDPOINT_ARCH="arm"
        ;;
    *)
        ENDPOINT_ARCH="amd64"  # default
        ;;
esac

# ----- Cleanup and Download Functions -----

cleanup() {
    echo -e "${blue}Cleaning up temporary files...${reset}"
    rm -rf "$TEMP_DIR"
    echo -e "${green}Cleanup complete.${reset}"
}
trap cleanup EXIT INT TERM

download_file() {
    local url="$1"
    local output="$2"
    local msg="$3"
    
    echo -e "${cyan}Downloading $msg...${reset}"
    
    if command -v curl &>/dev/null; then
        if ! curl -L -o "$output" --retry 3 --retry-delay 2 -m 60 -# "$url"; then
            error_exit "Download failed. Please check your internet connection."
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --show-progress -O "$output" --tries=3 --timeout=60 "$url"; then
            error_exit "Download failed. Please check your internet connection."
        fi
    else
        error_exit "curl or wget not found. Please install one of them."
    fi
}

download_warpendpoint() {
    local endpoint_path="$TEMP_DIR/warpendpoint"
    
    if [[ ! -f "$endpoint_path" ]]; then
        download_file "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/endip/$ENDPOINT_ARCH" "$endpoint_path" "warpendpoint"
        chmod +x "$endpoint_path"
        
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "warpendpoint is not executable or is corrupted."
        fi
    fi
}

# ----- IP Generation Functions -----

generate_ipv4() {
    echo -e "${blue}Generating IPv4 addresses...${reset}"
    local total=100
    local bases=("162.159.192" "162.159.193" "162.159.194" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99" "188.114.100" "188.114.101")
    
    > "$IP_FILE"
    declare -A ip_set=()
    local count=0
    while [ $count -lt $total ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local ip="${bases[$idx]}.$(( RANDOM % 256 ))"
        if [[ -z "${ip_set[$ip]}" ]]; then
            ip_set["$ip"]=1
            echo "$ip" >> "$IP_FILE"
            count=$((count+1))
        fi
    done
    echo -e "${green}$total IPv4 addresses generated.${reset}"
}

generate_ipv6() {
    echo -e "${blue}Generating IPv6 addresses...${reset}"
    local total=100
    local bases=("2606:4700:d0::" "2606:4700:d1::" "2606:4700:110::")
    
    rand_hex() {
        printf '%x' $(( RANDOM % 65536 ))
    }
    
    > "$IP_FILE"
    declare -A ip_set=()
    local count=0
    while [ $count -lt $total ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local seg1=$(rand_hex)
        local seg2=$(rand_hex)
        local seg3=$(rand_hex)
        local seg4=$(rand_hex)
        local ip="[${bases[$idx]}${seg1}:${seg2}:${seg3}:${seg4}]"
        if [[ -z "${ip_set[$ip]}" ]]; then
            ip_set["$ip"]=1
            echo "$ip" >> "$IP_FILE"
            count=$((count+1))
        fi
    done
    echo -e "${green}$total IPv6 addresses generated.${reset}"
}

# ----- WireGuard Key Generation -----

generate_wg_keys() {
    if command -v wg &>/dev/null; then
        local private_key
        local public_key
        private_key=$(wg genkey)
        public_key=$(echo "$private_key" | wg pubkey)
        echo "$private_key,$public_key"
    else
        error_exit "wireguard-tools not installed. Please install wg."
    fi
}

# ----- Performance Test Functions -----

test_bandwidth() {
    local ip="$1"
    local temp_file="$TEMP_DIR/speedtest.tmp"
    local size_kb=1024  # 1MB test

    download_speed=$(curl -s -o "$temp_file" --connect-to "speed.cloudflare.com:443:$ip:443" "https://speed.cloudflare.com/__down?bytes=$((size_kb*1024))" -w "%{speed_download}" 2>/dev/null)
    download_speed=$(echo "$download_speed / 1024" | bc -l | xargs printf "%.2f")
    
    upload_speed=$(curl -s -X POST --data-binary @"$temp_file" --connect-to "speed.cloudflare.com:443:$ip:443" "https://speed.cloudflare.com/__up" -w "%{speed_upload}" 2>/dev/null)
    upload_speed=$(echo "$upload_speed / 1024" | bc -l | xargs printf "%.2f")
    
    echo "$download_speed,$upload_speed"
}

test_stability() {
    local ip="$1"
    local count=10
    local results=()
    local sum=0
    local jitter=0
    local packet_loss=0
    
    for ((i=0; i<count; i++)); do
        if [[ "$OSTYPE" == "darwin"* ]]; then
            response=$(timeout 2 ping -c 1 "$ip" 2>/dev/null | grep "time=" | awk -F "time=" '{print $2}' | cut -d ' ' -f 1)
        else
            response=$(timeout 2 ping -c 1 -W 2 "$ip" 2>/dev/null | grep "time=" | awk -F "time=" '{print $2}' | cut -d ' ' -f 1)
        fi
        if [[ -n "$response" ]]; then
            results+=("$response")
            sum=$(echo "$sum + $response" | bc -l)
        else
            ((packet_loss++))
        fi
        sleep 0.2
    done
    
    local avg=0
    if [[ ${#results[@]} -gt 0 ]]; then
        avg=$(echo "scale=2; $sum / ${#results[@]}" | bc -l)
    fi
    
    if [[ ${#results[@]} -gt 1 ]]; then
        local sum_sq_diff=0
        for r in "${results[@]}"; do
            sum_sq_diff=$(echo "$sum_sq_diff + ($r - $avg)^2" | bc -l)
        done
        jitter=$(echo "scale=2; sqrt($sum_sq_diff / ${#results[@]})" | bc -l)
    fi
    
    packet_loss=$(echo "scale=2; ($packet_loss * 100) / $count" | bc -l)
    
    echo "$avg,$jitter,$packet_loss"
}

find_optimal_mtu() {
    local ip="$1"
    local start_mtu=1500
    local min_mtu=576
    local best_mtu=$start_mtu
    
    echo "Finding optimal MTU for $ip..."
    while [[ $best_mtu -gt $min_mtu ]]; do
        if [[ "$OSTYPE" == "darwin"* ]]; then
            if ping -c 1 -s $((best_mtu - 28)) "$ip" &>/dev/null; then
                break
            fi
        else
            if ping -c 1 -M do -s $((best_mtu - 28)) "$ip" &>/dev/null; then
                break
            fi
        fi
        best_mtu=$((best_mtu - 10))
    done
    echo "Optimal MTU: $best_mtu"
}

test_dns_leak() {
    local ip="$1"
    local dns_server="1.1.1.1"
    local test_domain="whoami.cloudflare.com"
    
    echo "Testing DNS Leak for $ip..."
    local dns_result=$(dig +short @"$dns_server" "$test_domain" TXT | tr -d '"')
    echo "DNS Leak Test Result: $dns_result"
}

check_geoip() {
    local ip="$1"
    local geo_data=$(curl -s "https://ipinfo.io/$ip/json")
    local country=$(echo "$geo_data" | grep -oP '"country": "\K[^"]+')
    local region=$(echo "$geo_data" | grep -oP '"region": "\K[^"]+')
    local city=$(echo "$geo_data" | grep -oP '"city": "\K[^"]+')
    echo "GeoIP info for $ip: Country: $country, Region: $region, City: $city"
}

run_all_tests() {
    local ip="$1"
    echo -e "${magenta}Running performance tests for IP: $ip${reset}"
    
    echo -e "${cyan}Bandwidth Test (Download, Upload in KB/s):${reset}"
    bw_result=$(test_bandwidth "$ip")
    echo -e "${blue}$bw_result${reset}"
    
    echo -e "${cyan}Stability Test (Average, Jitter, Packet Loss):${reset}"
    stability_result=$(test_stability "$ip")
    echo -e "${blue}$stability_result${reset}"
    
    echo -e "${cyan}Optimal MTU Test:${reset}"
    mtu_result=$(find_optimal_mtu "$ip")
    echo -e "${blue}$mtu_result${reset}"
    
    echo -e "${cyan}DNS Leak Test:${reset}"
    dns_result=$(test_dns_leak "$ip")
    echo -e "${blue}$dns_result${reset}"
    
    echo -e "${cyan}GeoIP Info:${reset}"
    geo_result=$(check_geoip "$ip")
    echo -e "${blue}$geo_result${reset}"
}

# ----- Parallel IP Scanning -----

parallel_scan() {
    local ip_type="$1"
    local endpoint_path="$TEMP_DIR/warpendpoint"
    local batch_size=10
    local total_ips
    total_ips=$(wc -l < "$IP_FILE")
    local batches=$(( (total_ips + batch_size - 1) / batch_size ))
    
    echo -e "${blue}Scanning IP addresses in parallel...${reset}"
    if [[ "$OSTYPE" != "darwin"* ]]; then
        ulimit -n 102400 2>/dev/null || ulimit -n 4096 2>/dev/null || true
    fi
    if [[ ! -x "$endpoint_path" ]]; then
        chmod +x "$endpoint_path" 2>/dev/null
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "warpendpoint is not executable."
        fi
    fi
    
    > "$RESULT_FILE"
    for ((i=0; i<batches; i++)); do
        local start=$(( i * batch_size + 1 ))
        local end=$(( start + batch_size - 1 ))
        local batch_file="$TEMP_DIR/batch_$i.txt"
        sed -n "${start},${end}p" "$IP_FILE" > "$batch_file"
        (
            "$endpoint_path" -f "$batch_file" 2>/dev/null | \
            awk -F, '$3!="timeout ms" {print "Endpoint: "$1" | Delay: "$3}' >> "$RESULT_FILE"
        ) &
        echo -ne "\r${cyan}Progress: $(( i * 100 / batches ))%${reset}"
    done
    wait
    echo -e "\r${green}Progress: 100%${reset}"
    rm -f "$TEMP_DIR"/batch_*.txt
    if [[ ! -s "$RESULT_FILE" ]]; then
        error_exit "No scan results obtained."
    fi
}

# ----- Get 10 Clean IPs -----

get_clean_ips() {
    local ip_type="$1"
    local clean_file="$TEMP_DIR/clean_ips.txt"
    rm -f "$clean_file"
    touch "$clean_file"
    while true; do
         if [[ "$ip_type" == "ipv4" ]]; then
             generate_ipv4
         else
             generate_ipv6
         fi
         parallel_scan "$ip_type"
         sed -E 's/^Endpoint: ([^ ]+) \| Delay:.*$/\1/' "$RESULT_FILE" >> "$clean_file"
         sort -u "$clean_file" -o "$clean_file"
         local count
         count=$(wc -l < "$clean_file")
         if (( count >= 10 )); then
              break
         else
              echo -e "${blue}Found $count clean IPs. Generating more...${reset}"
         fi
    done
    cp "$clean_file" "$BEST_IPS_FILE"
}

# ----- Scan Clean IPs and Display Results -----

scan_clean_ips() {
    local ip_type="$1"
    clear
    echo -e "${magenta}Scanning for clean ${ip_type} IPs...${reset}"
    download_warpendpoint
    get_clean_ips "$ip_type"
    
    echo ""
    echo -e "${green}Clean IPs found:${reset}"
    nl -w2 -s'. ' "$BEST_IPS_FILE"
    
    echo ""
    echo -ne "${cyan}Enter the index (1-10) of the IP to run performance tests on (or press Enter to skip): ${reset}"
    read -r index
    if [[ -n "$index" ]]; then
         selected_ip=$(sed -n "${index}p" "$BEST_IPS_FILE")
         if [[ -n "$selected_ip" ]]; then
              run_all_tests "$selected_ip"
         else
              echo -e "${red}Invalid index.${reset}"
         fi
    fi
    
    echo ""
    echo -ne "${cyan}Return to main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
         main_menu
    fi
}

# ----- Warp Hidify Feature -----

warp_hidify() {
    local ip_type="ipv4"
    if [[ "$1" == "6" ]]; then
         ip_type="ipv6"
    fi
    local best_ip=""
    if [[ -s "$BEST_IPS_FILE" ]]; then
         best_ip=$(head -n 1 "$BEST_IPS_FILE")
    else
         get_clean_ips "$ip_type"
         best_ip=$(head -n 1 "$BEST_IPS_FILE")
    fi
    if [[ -z "$best_ip" ]]; then
         error_exit "No valid IP found."
    fi
    local warp_uri=""
    if [[ "$ip_type" == "ipv4" ]]; then
         local port=1843
         local ip_addr=$(echo "$best_ip" | cut -d: -f1)
         warp_uri="warp://$ip_addr:$port/?ifp=5-10@void1x0"
    else
         local port=878
         local ip_addr=$(echo "$best_ip" | sed 's/^\[\(.*\)\]:.*$/\1/')
         warp_uri="warp://[$ip_addr]:$port/?ifp=5-10@void1x0"
    fi
    echo "$warp_uri" > "$TEMP_DIR/warp_hidify.txt"
    echo -e "${green}Warp Hidify URI generated:${reset}"
    echo "$warp_uri"
    
    echo ""
    echo -ne "${cyan}Return to main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
         main_menu
    fi
}

# ----- WireGuard Config Generation -----

generate_wg_config() {
    echo -ne "${cyan}Do you want to generate a WireGuard configuration? (y/n): ${reset}"
    read -r resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
        local endpoint=""
        echo -ne "${cyan}Do you want to scan for the best endpoint IP? (y/n): ${reset}"
        read -r scan_choice
        if [[ "$scan_choice" =~ ^[Yy]$ ]]; then
            echo -e "${cyan}Choose IP version for scanning:${reset}"
            echo -e "${yellow}[1] IPv4${reset}"
            echo -e "${yellow}[2] IPv6${reset}"
            echo -ne "${cyan}Your choice: ${reset}"
            read -r ip_choice
            case "$ip_choice" in
                1)
                    scan_clean_ips "ipv4"
                    endpoint=$(head -n 1 "$BEST_IPS_FILE")
                    ;;
                2)
                    scan_clean_ips "ipv6"
                    endpoint=$(head -n 1 "$BEST_IPS_FILE")
                    ;;
                *)
                    echo -e "${yellow}Invalid selection. Using default endpoint.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        else
            echo -e "${cyan}Select endpoint option:${reset}"
            echo -e "${yellow}[1] Default (engage.cloudflareclient.com:2408)${reset}"
            echo -e "${yellow}[2] New Warp (engage.cloudflareclient.com:2409)${reset}"
            echo -ne "${cyan}Your choice: ${reset}"
            read -r ep_choice
            case "$ep_choice" in
                1)
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
                2)
                    endpoint="engage.cloudflareclient.com:2409"
                    ;;
                *)
                    echo -e "${yellow}Invalid selection. Using default endpoint.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        fi
        
        keys=$(generate_wg_keys)
        private_key=$(echo "$keys" | cut -d',' -f1)
        public_key=$(echo "$keys" | cut -d',' -f2)
        
        local wg_ipv4="172.16.0.2/32"
        local wg_ipv6="2606:4700:110:848e:fec7:926a:f8d:1ca/128"
        
        echo -ne "${cyan}Enter config file path (default: $DEFAULT_CONFIG_PATH): ${reset}"
        read -r config_path
        if [[ -z "$config_path" ]]; then
            config_path="$DEFAULT_CONFIG_PATH"
        fi
        
        mkdir -p "$(dirname "$config_path")" 2>/dev/null
        
        cat > "$config_path" <<EOF
[Interface]
PrivateKey = $private_key
Address = $wg_ipv4, $wg_ipv6
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = $public_key
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint
EOF
        
        if [[ $? -eq 0 ]]; then
            echo -e "${green}WireGuard configuration generated and saved in $config_path${reset}"
            chmod 600 "$config_path" 2>/dev/null || true
            
            echo -e "${magenta}Configuration details:${reset}"
            echo -e "${cyan}Private Key: ${green}$private_key${reset}"
            echo -e "${cyan}Public Key: ${green}$public_key${reset}"
            echo -e "${cyan}IPv4 Address: ${green}$wg_ipv4${reset}"
            echo -e "${cyan}IPv6 Address: ${green}$wg_ipv6${reset}"
            echo -e "${cyan}Endpoint: ${green}$endpoint${reset}"
            echo -e "${cyan}DNS: ${green}1.1.1.1, 1.0.0.1${reset}"
            echo -e "${cyan}MTU: ${green}1280${reset}"
        else
            echo -e "${red}Error writing config file. Check permissions.${reset}"
        fi
    else
        echo -e "${yellow}WireGuard config generation canceled.${reset}"
    fi
    
    echo ""
    echo -ne "${cyan}Return to main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
        main_menu
    fi
}

# ----- Main Menu -----

main_menu() {
    clear
    echo -e "${magenta}Warp IP Scanner & WireGuard Config Generator v$VERSION${reset}"
    echo -e "${blue}Choose an option:${reset}"
    echo -e "${yellow}[1] Scan IPv4${reset}"
    echo -e "${yellow}[2] Scan IPv6${reset}"
    echo -e "${yellow}[3] Generate WireGuard Config${reset}"
    echo -e "${yellow}[4] Warp Hidify${reset}"
    echo -e "${yellow}[0] Exit${reset}"
    echo -ne "${cyan}Your choice: ${reset}"
    read -r choice
    case "$choice" in
        1)
            scan_clean_ips "ipv4"
            ;;
        2)
            scan_clean_ips "ipv6"
            ;;
        3)
            generate_wg_config
            ;;
        4)
            warp_hidify
            ;;
        0)
            echo -e "${green}Exiting...${reset}"
            exit 0
            ;;
        *)
            echo -e "${red}Invalid selection.${reset}"
            sleep 2
            main_menu
            ;;
    esac
}

for cmd in grep sort; do
    if ! command -v "$cmd" &>/dev/null; then
        error_exit "Command $cmd not found. Please install essential packages."
    fi
done

main_menu
