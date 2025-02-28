#!/bin/bash
# Warp IP Scanner & WireGuard Config Generator

VERSION="1.1"

# ----- Set Variables and Constants -----

# Colors (enabled if the terminal supports color)
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
    # macOS
    DEFAULT_CONFIG_PATH="$HOME/wg-config.conf"
    TEMP_DIR="/tmp/warp-scanner"
elif [[ "$OSTYPE" == "linux-android"* || -d "/storage/emulated/0" ]]; then
    # Android (Termux or similar)
    DEFAULT_CONFIG_PATH="/storage/emulated/0/wg-config.conf"
    TEMP_DIR="$HOME/warp-scanner-tmp"
else
    # Linux and other systems
    DEFAULT_CONFIG_PATH="$HOME/wg-config.conf"
    TEMP_DIR="/tmp/warp-scanner"
fi

# Create temporary directory
mkdir -p "$TEMP_DIR"
IP_FILE="$TEMP_DIR/ip.txt"
RESULT_FILE="$TEMP_DIR/result.txt"
CSV_FILE="$TEMP_DIR/result.csv"
BEST_IPS_FILE="$TEMP_DIR/best_ips.txt"

# Determine system architecture for downloading the appropriate warpendpoint file
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

# ----- Functions and Operations -----

# Display error message and exit
error_exit() {
    echo -e "${red}Error: $1${reset}" >&2
    exit 1
}

# Display progress information
show_progress() {
    echo -e "${blue}$1${reset}"
}

# Clean up temporary files
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
        echo -e "${yellow}A new version ($latest_version) is available. Please visit https://github.com/void1x0/WARP-Scanner to update.${reset}"
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

# Download warpendpoint if not already available in the TEMP_DIR
download_warpendpoint() {
    local endpoint_path="$TEMP_DIR/warpendpoint"
    
    if [[ ! -f "$endpoint_path" ]]; then
        download_file "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/endip/$ENDPOINT_ARCH" "$endpoint_path" "warpendpoint"
        chmod +x "$endpoint_path"
        
        # Verify successful download
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "The warpendpoint file is not executable or is corrupted."
        fi
    fi
}

# Generate 100 unique IPv4 addresses from Warp ranges
generate_ipv4() {
    show_progress "Generating IPv4 addresses..."
    local total=100
    local bases=("162.159.192" "162.159.193" "162.159.194" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99" "188.114.100" "188.114.101")
    
    local temp_array=()
    while [ "${#temp_array[@]}" -lt "$total" ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local ip="${bases[$idx]}.$(( RANDOM % 256 ))"
        
        # Check for duplicate IPs
        local duplicate=0
        for existing_ip in "${temp_array[@]}"; do
            if [[ "$existing_ip" == "$ip" ]]; then
                duplicate=1
                break
            fi
        done
        
        if [[ "$duplicate" -eq 0 ]]; then
            temp_array+=("$ip")
        fi
    done
    
    printf "%s\n" "${temp_array[@]}" > "$IP_FILE"
    echo -e "${green}$total IPv4 addresses generated.${reset}"
}

# Generate 100 unique IPv6 addresses from Warp ranges
generate_ipv6() {
    show_progress "Generating IPv6 addresses..."
    local total=100
    local bases=("2606:4700:d0::" "2606:4700:d1::" "2606:4700:110::")
    
    rand_hex() {
        printf '%x' $(( RANDOM % 65536 ))
    }
    
    local temp_array=()
    while [ "${#temp_array[@]}" -lt "$total" ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local seg1=$(rand_hex)
        local seg2=$(rand_hex)
        local seg3=$(rand_hex)
        local seg4=$(rand_hex)
        local ip="[${bases[$idx]}${seg1}:${seg2}:${seg3}:${seg4}]"
        
        # Check for duplicate IPs
        local duplicate=0
        for existing_ip in "${temp_array[@]}"; do
            if [[ "$existing_ip" == "$ip" ]]; then
                duplicate=1
                break
            fi
        done
        
        if [[ "$duplicate" -eq 0 ]]; then
            temp_array+=("$ip")
        fi
    done
    
    printf "%s\n" "${temp_array[@]}" > "$IP_FILE"
    echo -e "${green}$total IPv6 addresses generated.${reset}"
}

# Convert CSV results to a plain TXT file
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

# Parallel scan of IP addresses to improve speed
parallel_scan() {
    local ip_type="$1"
    local endpoint_path="$TEMP_DIR/warpendpoint"
    local batch_size=10
    local total_ips
    total_ips=$(wc -l < "$IP_FILE")
    local batches=$((total_ips / batch_size))
    
    show_progress "Scanning IP addresses in parallel..."
    
    # Set ulimit for non-macOS platforms (macOS has specific limitations)
    if [[ "$OSTYPE" != "darwin"* ]]; then
        ulimit -n 102400 2>/dev/null || ulimit -n 4096 2>/dev/null || true
    fi
    
    # Ensure warpendpoint is executable
    if [[ ! -x "$endpoint_path" ]]; then
        chmod +x "$endpoint_path" 2>/dev/null
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "warpendpoint is not executable."
        fi
    fi
    
    # Divide the IP file into smaller batches for parallel scanning
    for ((i=0; i<batches; i++)); do
        local start=$((i * batch_size + 1))
        local end=$((start + batch_size - 1))
        
        local batch_file="$TEMP_DIR/batch_$i.txt"
        sed -n "${start},${end}p" "$IP_FILE" > "$batch_file"
        
        (
            "$endpoint_path" -f "$batch_file" -o "$TEMP_DIR/result_$i.csv" >/dev/null 2>&1
        ) &
        
        echo -ne "\r${cyan}Progress: $((i * 100 / batches))%${reset}"
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

# Execute scan and display results
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
        
        # Extract the best IP addresses
        local best_ipv4=""
        local best_ipv6=""
        local delay=""
        
        if [[ "$ip_type" == "ipv4" ]]; then
            best_ipv4=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n 1)
            delay=$(grep -oE "[0-9]+ ms|timeout" "$RESULT_FILE" | head -n 1)
        else
            best_ipv6=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n 1)
            delay=$(grep -oE "[0-9]+ ms|timeout" "$RESULT_FILE" | head -n 1)
        fi
        
        echo ""
        echo -e "${green}Results saved in $RESULT_FILE${reset}"
        echo ""
        
        if [[ "$ip_type" == "ipv4" && -n "$best_ipv4" ]]; then
            echo -e "${magenta}******** Best IPv4 ********${reset}"
            echo -e "${blue}$best_ipv4${reset}"
            echo -e "${blue}Delay: ${green}[$delay]${reset}"
            echo "$best_ipv4" > "$BEST_IPS_FILE"
        elif [[ "$ip_type" == "ipv6" && -n "$best_ipv6" ]]; then
            echo -e "${magenta}******** Best IPv6 ********${reset}"
            echo -e "${blue}$best_ipv6${reset}"
            echo -e "${blue}Delay: ${green}[$delay]${reset}"
            echo "$best_ipv6" > "$BEST_IPS_FILE"
        else
            echo -e "${red}No valid IP addresses found.${reset}"
        fi
    else
        echo -e "${red}$RESULT_FILE not found. The scan may have failed.${reset}"
    fi
    
    echo ""
    echo -ne "${cyan}Return to the main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
        main_menu
    fi
}

# Warp Hidify Feature
warp_hidify() {
    local ip_type="ipv4"
    # If user wishes to use IPv6, pass "ipv6" as an argument (optional)
    if [[ "$1" == "ipv6" ]]; then
         ip_type="ipv6"
    fi
    local best_ip=""
    if [[ -s "$BEST_IPS_FILE" ]]; then
         best_ip=$(head -n 1 "$BEST_IPS_FILE")
    else
         scan_results "$ip_type"
         best_ip=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n 1)
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
    echo -ne "${cyan}Return to the main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
         main_menu
    fi
}

# Generate a WireGuard configuration file with new keys
generate_wg_config() {
    echo -ne "${cyan}Do you want to generate a WireGuard configuration? (y/n): ${reset}"
    read -r resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
        local endpoint=""
        
        echo -ne "${cyan}Do you want to scan for the best endpoint IP? (y/n): ${reset}"
        read -r scan_choice
        if [[ "$scan_choice" =~ ^[Yy]$ ]]; then
            echo -e "${cyan}Select the IP type for scanning: ${reset}"
            echo -e "${yellow}[1] IPv4${reset}"
            echo -e "${yellow}[2] IPv6${reset}"
            echo -ne "${cyan}Your choice: ${reset}"
            read -r ip_choice
            
            case "$ip_choice" in
                1)
                    download_warpendpoint
                    generate_ipv4
                    parallel_scan "ipv4"
                    endpoint=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n 1)
                    ;;
                2)
                    download_warpendpoint
                    generate_ipv6
                    parallel_scan "ipv6"
                    endpoint=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n 1)
                    ;;
                *)
                    echo -e "${yellow}Invalid selection. Using the default endpoint.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        else
            echo -e "${cyan}Select the endpoint option:${reset}"
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
                    echo -e "${yellow}Invalid selection. Using the default endpoint.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        fi
        
        # Generate new WireGuard keys
        local private_key=""
        local public_key=""
        
        if command -v wg &>/dev/null; then
            private_key=$(wg genkey)
            public_key=$(echo "$private_key" | wg pubkey)
        else
            echo -e "${red}wireguard-tools not installed. Please install wg.${reset}"
            echo -e "${yellow}Returning to the main menu...${reset}"
            sleep 2
            main_menu
            return
        fi
        
        # Default client addresses per sample configuration
        local wg_ipv4="172.16.0.2/32"
        local wg_ipv6="2606:4700:110:848e:fec7:926a:f8d:1ca/128"
        
        echo -ne "${cyan}Enter the config file path (default: $DEFAULT_CONFIG_PATH): ${reset}"
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
            
            echo -e "${magenta}Configuration Details:${reset}"
            echo -e "${cyan}Private Key: ${green}$private_key${reset}"
            echo -e "${cyan}Public Key: ${green}$public_key${reset}"
            echo -e "${cyan}IPv4 Address: ${green}$wg_ipv4${reset}"
            echo -e "${cyan}IPv6 Address: ${green}$wg_ipv6${reset}"
            echo -e "${cyan}Endpoint: ${green}$endpoint${reset}"
            echo -e "${cyan}DNS: ${green}1.1.1.1, 1.0.0.1${reset}"
            echo -e "${cyan}MTU: ${green}1280${reset}"
        else
            echo -e "${red}Error writing config file. Please check your permissions.${reset}"
        fi
    else
        echo -e "${yellow}WireGuard configuration generation canceled.${reset}"
    fi
    
    echo ""
    echo -ne "${cyan}Return to the main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
        main_menu
    fi
}

# Main Menu
main_menu() {
    clear
    echo -e "${magenta}Warp IP Scanner & WireGuard Config Generator v$VERSION${reset}"
    check_update
    echo -e "${blue}Please select an option:${reset}"
    echo -e "${yellow}[1] Scan IPv4${reset}"
    echo -e "${yellow}[2] Scan IPv6${reset}"
    echo -e "${yellow}[3] Generate WireGuard Config${reset}"
    echo -e "${yellow}[4] Warp Hidify${reset}"
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

# ----- Start the Program -----

# Check for essential commands
for cmd in grep sort; do
    if ! command -v "$cmd" &>/dev/null; then
        error_exit "Command $cmd not found. Please install the essential system packages."
    fi
done

# Start by displaying the main menu
main_menu
