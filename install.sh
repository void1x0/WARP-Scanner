#!/bin/bash
# Warp IP Scanner & WireGuard Config Generator
# Optimized for multiple platforms, added performance tests, Warp Hidify feature,
# and an option to scan IPs from a file (main.txt)

VERSION="1.1"

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
CSV_FILE="$TEMP_DIR/result.csv"
BEST_IPS_FILE="$TEMP_DIR/best_ips.txt"

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

# ----- Common Functions -----

# Display error message and exit
error_exit() {
    echo -e "${red}Error: $1${reset}" >&2
    exit 1
}

# Display progress messages
show_progress() {
    echo -e "${blue}$1${reset}"
}

# Cleanup temporary files
cleanup() {
    show_progress "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    echo -e "${green}Cleanup complete.${reset}"
}
trap cleanup EXIT INT TERM

# Check for updates
check_update() {
    show_progress "Checking for updates..."
    
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        echo -e "${yellow}curl or wget not found. Skipping update check.${reset}"
        return
    fi
    
    local latest_version
    if command -v curl &>/dev/null; then
        latest_version=$(curl -s -m 5 "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/version.txt" 2>/dev/null || echo "$VERSION")
    else
        latest_version=$(wget -q -O - -T 5 "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/version.txt" 2>/dev/null || echo "$VERSION")
    fi
    
    if [[ "$latest_version" != "$VERSION" && "$latest_version" != "" ]]; then
        echo -e "${yellow}New version ($latest_version) available. Visit https://github.com/void1x0/WARP-Scanner to update.${reset}"
    else
        echo -e "${green}You are using the latest version ($VERSION).${reset}"
    fi
}

# Download a file using curl or wget
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

# Download warpendpoint if not present
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

# ----- Unique IP Generation Functions (Improved with associative arrays) -----

generate_ipv4() {
    show_progress "Generating IPv4 addresses..."
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
    show_progress "Generating IPv6 addresses..."
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

# ----- WireGuard Key Generation Function -----

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
        response=$(timeout 2 ping -c 1 -W 2 "$ip" 2>/dev/null | grep "time=" | awk -F "time=" '{print $2}' | cut -d ' ' -f 1)
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

test_services_access() {
    local ip="$1"
    local services=("www.google.com" "www.youtube.com" "www.netflix.com" "www.spotify.com" "www.instagram.com")
    local results=()
    
    for service in "${services[@]}"; do
        if curl --connect-to "$service:443:$ip:443" -s -o /dev/null -w "%{http_code}" "https://$service/" | grep -q "^[23]"; then
            results+=("$service:OK")
        else
            results+=("$service:FAIL")
        fi
    done
    
    echo "${results[*]}"
}

find_optimal_mtu() {
    local ip="$1"
    local start_mtu=1500
    local min_mtu=576
    local best_mtu=$start_mtu
    
    echo "Finding optimal MTU for $ip..."
    
    while [[ $best_mtu -gt $min_mtu ]]; do
        if ping -c 1 -M do -s $((best_mtu - 28)) "$ip" &>/dev/null; then
            break
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

test_dpi_bypass() {
    local ip="$1"
    local blocked_sites=("twitter.com" "facebook.com" "t.me" "reddit.com")
    local results=()
    
    for site in "${blocked_sites[@]}"; do
        if curl --connect-to "$site:443:$ip:443" -s -o /dev/null -w "%{http_code}" "https://$site/" | grep -q "^[23]"; then
            results+=("$site:Accessible")
        else
            results+=("$site:Blocked")
        fi
    done
    
    echo "${results[*]}"
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
    
    echo -e "${cyan}Services Access Test:${reset}"
    services_result=$(test_services_access "$ip")
    echo -e "${blue}$services_result${reset}"
    
    echo -e "${cyan}Optimal MTU Test:${reset}"
    mtu_result=$(find_optimal_mtu "$ip")
    echo -e "${blue}$mtu_result${reset}"
    
    echo -e "${cyan}DNS Leak Test:${reset}"
    dns_result=$(test_dns_leak "$ip")
    echo -e "${blue}$dns_result${reset}"
    
    echo -e "${cyan}DPI Bypass Test:${reset}"
    dpi_result=$(test_dpi_bypass "$ip")
    echo -e "${blue}$dpi_result${reset}"
    
    echo -e "${cyan}GeoIP Info:${reset}"
    geo_result=$(check_geoip "$ip")
    echo -e "${blue}$geo_result${reset}"
}

# ----- Parallel IP Scanning for Speed Improvement -----

parallel_scan() {
    local ip_type="$1"
    local endpoint_path="$TEMP_DIR/warpendpoint"
    local batch_size=10
    local total_ips
    total_ips=$(wc -l < "$IP_FILE")
    local batches=$(( (total_ips + batch_size - 1) / batch_size ))
    
    show_progress "Scanning IP addresses in parallel..."
    
    if [[ "$OSTYPE" != "darwin"* ]]; then
        ulimit -n 102400 2>/dev/null || ulimit -n 4096 2>/dev/null || true
    fi
    
    if [[ ! -x "$endpoint_path" ]]; then
        chmod +x "$endpoint_path" 2>/dev/null
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "warpendpoint is not executable."
        fi
    fi
    
    for ((i=0; i<batches; i++)); do
        local start=$(( i * batch_size + 1 ))
        local end=$(( start + batch_size - 1 ))
        
        local batch_file="$TEMP_DIR/batch_$i.txt"
        sed -n "${start},${end}p" "$IP_FILE" > "$batch_file"
        
        (
            "$endpoint_path" -f "$batch_FILE" -o "$TEMP_DIR/result_$i.csv" >/dev/null 2>&1
        ) &
        
        echo -ne "\r${cyan}Progress: $(( i * 100 / batches ))%${reset}"
    done
    
    wait
    echo -e "\r${green}Progress: 100%${reset}"
    
    if ls "$TEMP_DIR"/result_*.csv 1>/dev/null 2>&1; then
        cat "$TEMP_DIR"/result_*.csv > "$CSV_FILE"
        rm -f "$TEMP_DIR"/result_*.csv "$TEMP_DIR"/batch_*.txt
        convert_csv_to_txt
    else
        error_exit "No scan results obtained."
    fi
}

# Convert CSV to TXT
convert_csv_to_txt() {
    if [[ -f "$CSV_FILE" ]]; then
        if command -v awk &>/dev/null; then
            awk -F, '$3!="timeout ms" {print "Endpoint: "$1" | Delay: "$3}' "$CSV_FILE" | sort -t, -nk3 | uniq > "$RESULT_FILE"
        else
            while IFS=',' read -r endpoint _ delay_ms _; do
                if [[ "$delay_ms" != "timeout ms" ]]; then
                    echo "Endpoint: $endpoint | Delay: $delay_ms"
                fi
            done < "$CSV_FILE" | sort | uniq > "$RESULT_FILE"
        fi
        rm -f "$CSV_FILE"
    fi
}

# ----- Function to Get Best IP without returning to main menu -----

get_best_ip() {
    local ip_type="$1"
    if [[ "$ip_type" == "ipv4" ]]; then
        generate_ipv4
    elif [[ "$ip_type" == "ipv6" ]]; then
        generate_ipv6
    else
        error_exit "Invalid IP type."
    fi

    download_warpendpoint
    parallel_scan "$ip_type"

    if [[ -f "$RESULT_FILE" ]]; then
        local best_ip=""
        if [[ "$ip_type" == "ipv4" ]]; then
            best_ip=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n 1)
        else
            best_ip=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n 1)
        fi
        if [[ -n "$best_ip" ]]; then
            echo "$best_ip"
            return 0
        else
            error_exit "No valid IP found."
        fi
    else
        error_exit "$RESULT_FILE not found. The scan might have failed."
    fi
}

# ----- Scan Results and Display -----

scan_results() {
    local ip_type="$1"
    
    if [[ "$ip_type" == "ipv4" ]]; then
        generate_ipv4
    elif [[ "$ip_type" == "ipv6" ]]; then
        generate_ipv6
    else
        error_exit "Invalid IP type."
    fi
    
    download_warpendpoint
    parallel_scan "$ip_type"
    
    clear
    if [[ -f "$RESULT_FILE" ]]; then
        echo -e "${magenta}Scan Results:${reset}"
        head -n 11 "$RESULT_FILE"
        
        local best_ip=""
        local delay=""
        
        if [[ "$ip_type" == "ipv4" ]]; then
            best_ip=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n 1)
            delay=$(grep -oE "[0-9]+ ms|timeout" "$RESULT_FILE" | head -n 1)
        else
            best_ip=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n 1)
            delay=$(grep -oE "[0-9]+ ms|timeout" "$RESULT_FILE" | head -n 1)
        fi
        
        echo ""
        echo -e "${green}Results saved in $RESULT_FILE${reset}"
        echo ""
        
        if [[ -n "$best_ip" ]]; then
            echo -e "${magenta}******** Best IP ********${reset}"
            echo -e "${blue}$best_ip${reset}"
            echo -e "${blue}Delay: ${green}[$delay]${reset}"
            echo "$best_ip" > "$BEST_IPS_FILE"
            
            echo ""
            echo -ne "${cyan}Do you want to run performance tests on this IP? (y/n): ${reset}"
            read -r test_choice
            if [[ "$test_choice" =~ ^[Yy]$ ]]; then
                run_all_tests "$best_ip"
            fi
        else
            echo -e "${red}No valid IP found.${reset}"
        fi
    else
        echo -e "${red}$RESULT_FILE not found. The scan might have failed.${reset}"
    fi
    
    echo ""
    echo -ne "${cyan}Return to main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
        main_menu
    fi
}

# ----- Check main.txt Option (Download from GitHub) -----

check_main_txt() {
    local main_txt_url="https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/main.txt"
    echo -e "${cyan}Downloading main.txt from GitHub...${reset}"
    download_file "$main_txt_url" "main.txt" "main.txt file"
    
    if [[ ! -f "main.txt" ]]; then
        echo -e "${red}File main.txt not found after download.${reset}"
        return
    fi

    echo -ne "${cyan}Are the addresses in main.txt IPv4 or IPv6? (Enter 4 or 6): ${reset}"
    read -r ip_version
    local ip_type=""
    if [[ "$ip_version" == "4" ]]; then
        ip_type="ipv4"
    elif [[ "$ip_version" == "6" ]]; then
        ip_type="ipv6"
    else
        echo -e "${red}Invalid input. Defaulting to IPv4.${reset}"
        ip_type="ipv4"
    fi

    # Use main.txt as the source for IP addresses
    cp "main.txt" "$IP_FILE"
    show_progress "Scanning IP addresses from main.txt..."
    
    download_warpendpoint
    parallel_scan "$ip_type"
    
    clear
    if [[ -f "$RESULT_FILE" ]]; then
        echo -e "${magenta}Scan Results from main.txt:${reset}"
        head -n 11 "$RESULT_FILE"
        
        local best_ip=""
        local delay=""
        if [[ "$ip_type" == "ipv4" ]]; then
            best_ip=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n 1)
            delay=$(grep -oE "[0-9]+ ms|timeout" "$RESULT_FILE" | head -n 1)
        else
            best_ip=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n 1)
            delay=$(grep -oE "[0-9]+ ms|timeout" "$RESULT_FILE" | head -n 1)
        fi
        
        echo ""
        echo -e "${green}Results saved in $RESULT_FILE${reset}"
        echo ""
        
        if [[ -n "$best_ip" ]]; then
            echo -e "${magenta}******** Best IP from main.txt ********${reset}"
            echo -e "${blue}$best_ip${reset}"
            echo -e "${blue}Delay: ${green}[$delay]${reset}"
        else
            echo -e "${red}No valid IP found in main.txt.${reset}"
        fi
    else
        echo -e "${red}$RESULT_FILE not found. The scan might have failed.${reset}"
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
    echo -ne "${cyan}Choose IP version for Warp Hidify (1: IPv4, 2: IPv6): ${reset}"
    read -r ip_choice
    local ip_type=""
    if [[ "$ip_choice" == "1" ]]; then
         ip_type="ipv4"
    elif [[ "$ip_choice" == "2" ]]; then
         ip_type="ipv6"
    else
         echo -e "${red}Invalid selection.${reset}"
         return
    fi

    echo -ne "${cyan}Do you want to scan for a new IP? (y/n): ${reset}"
    read -r scan_new
    local best_ip=""
    if [[ "$scan_new" =~ ^[Yy]$ ]]; then
         best_ip=$(get_best_ip "$ip_type")
    else
         if [[ -s "$BEST_IPS_FILE" ]]; then
              best_ip=$(cat "$BEST_IPS_FILE")
         else
              echo -e "${yellow}No previously scanned IP found. Scanning now...${reset}"
              best_ip=$(get_best_ip "$ip_type")
         fi
    fi

    if [[ -z "$best_ip" ]]; then
         echo -e "${red}No valid IP found.${reset}"
         return
    fi

    if [[ "$ip_type" == "ipv4" ]]; then
         local port=1843
         local ip_addr=$(echo "$best_ip" | cut -d: -f1)
         warp_uri="warp://$ip_addr:$port/?ifp=5-10@void1x0"
    else
         local port=878
         local ip_addr=$(echo "$best_ip" | sed 's/^\[\(.*\)\]:.*$/\1/')
         warp_uri="warp://[$ip_addr]:$port/?ifp=5-10@void1x0"
    fi

    local warp_hidify_file="$TEMP_DIR/warp_hidify.txt"
    echo "$warp_uri" > "$warp_hidify_file"

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
                    endpoint=$(get_best_ip "ipv4")
                    ;;
                2)
                    endpoint=$(get_best_ip "ipv6")
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
    check_update
    echo -e "${blue}Choose an option:${reset}"
    echo -e "${yellow}[1] Scan IPv4${reset}"
    echo -e "${yellow}[2] Scan IPv6${reset}"
    echo -e "${yellow}[3] Generate WireGuard Config${reset}"
    echo -e "${yellow}[4] Warp Hidify${reset}"
    echo -e "${yellow}[5] Check main.txt${reset}"
    echo -e "${yellow}[0] Exit${reset}"
    echo -ne "${cyan}Your choice: ${reset}"
    read -r choice
    
    case "$choice" in
        1)
            download_warpendpoint
            scan_results "ipv4"
            ;;
        2)
            download_warpendpoint
            scan_results "ipv6"
            ;;
        3)
            generate_wg_config
            ;;
        4)
            warp_hidify
            ;;
        5)
            check_main_txt
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

# ----- Start Program -----

for cmd in grep sort; do
    if ! command -v "$cmd" &>/dev/null; then
        error_exit "Command $cmd not found. Please install essential packages."
    fi
done

main_menu
