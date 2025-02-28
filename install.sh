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
BEST_IPS_FILE="$TEMP_DIR/best_ips.txt"

# ----- Functions -----

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

# Generate 100 unique IPv4 addresses from Warp ranges
generate_ipv4() {
    show_progress "Generating IPv4 addresses..."
    local total=100
    local bases=("162.159.192" "162.159.193" "162.159.194" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99" "188.114.100" "188.114.101")
    
    local temp_array=()
    while [ "${#temp_array[@]}" -lt "$total" ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local ip="${bases[$idx]}.$(( RANDOM % 256 ))"
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

# Generate 100 unique IPv6 addresses from the specified Warp bases
# (Only these bases will be used: "2606:4700:d0::", "2606:4700:d1::", "2606:4700:110::")
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

# Test the stability of an IP using ping (returns average delay, jitter, and packet loss)
test_stability() {
    local ip="$1"
    local count=10
    local results=()
    local sum=0
    local jitter=0
    local packet_loss=0

    for ((i=0; i<count; i++)); do
        if [[ "$OSTYPE" == "darwin"* ]]; then
            response=$(timeout 2 ping -c 1 "$ip" 2>/dev/null | grep "time=" | awk -F"time=" '{print $2}' | cut -d' ' -f1)
        else
            response=$(timeout 2 ping -c 1 -W 2 "$ip" 2>/dev/null | grep "time=" | awk -F"time=" '{print $2}' | cut -d' ' -f1)
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
    if [ "${#results[@]}" -gt 0 ]; then
        avg=$(echo "scale=2; $sum / ${#results[@]}" | bc -l)
    fi

    if [ "${#results[@]}" -gt 1 ]; then
        local sum_sq_diff=0
        for r in "${results[@]}"; do
            sum_sq_diff=$(echo "$sum_sq_diff + ($r - $avg)^2" | bc -l)
        done
        jitter=$(echo "scale=2; sqrt($sum_sq_diff / ${#results[@]})" | bc -l)
    fi

    packet_loss=$(echo "scale=2; ($packet_loss * 100) / $count" | bc -l)

    echo "$avg,$jitter,$packet_loss"
}

# Run detailed performance tests for an IP
run_all_tests() {
    local ip="$1"
    echo -e "${magenta}Running detailed performance tests for IP: $ip${reset}"
    
    echo -e "${cyan}Stability Test (Average, Jitter, Packet Loss):${reset}"
    stability_result=$(test_stability "$ip")
    echo -e "${blue}$stability_result${reset}"
    
    echo -e "${cyan}Optimal MTU Test (using ping test):${reset}"
    local start_mtu=1500
    local min_mtu=576
    local best_mtu=$start_mtu
    while [ $best_mtu -gt $min_mtu ]; do
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
    echo -e "${blue}Optimal MTU: $best_mtu${reset}"
    
    echo -e "${cyan}GeoIP Info (using ipinfo.io):${reset}"
    local geo_data=$(curl -s "https://ipinfo.io/$ip/json")
    local country=$(echo "$geo_data" | grep -oP '"country": "\K[^"]+')
    local region=$(echo "$geo_data" | grep -oP '"region": "\K[^"]+')
    local city=$(echo "$geo_data" | grep -oP '"city": "\K[^"]+')
    echo -e "${blue}GeoIP for $ip: Country: $country, Region: $region, City: $city${reset}"
}

# ----- Inline Scanning Method -----
inline_scan() {
    local ip_type="$1"
    if [ "$ip_type" = "ipv4" ]; then
         generate_ipv4
    elif [ "$ip_type" = "ipv6" ]; then
         generate_ipv6
    else
         error_exit "Invalid IP type."
    fi

    echo -e "${blue}Performing inline scan on generated IPs...${reset}"
    
    local best_ip=""
    local best_delay=99999
    local results=()
    
    while IFS= read -r ip; do
         result=$(test_stability "$ip")  # returns avg,jitter,packet_loss
         avg=$(echo "$result" | cut -d',' -f1)
         packet_loss=$(echo "$result" | cut -d',' -f3)
         results+=("$ip,$avg,$packet_loss")
         # Consider IP only if packet_loss is less than 100%
         if [ "$(echo "$packet_loss < 100" | bc -l)" -eq 1 ] && [ "$(echo "$avg < $best_delay" | bc -l)" -eq 1 ]; then
              best_delay="$avg"
              best_ip="$ip"
         fi
    done < "$IP_FILE"
    
    echo -e "${magenta}Inline Scan Results (Top 10 by average delay):${reset}"
    printf "%s\n" "${results[@]}" | sort -t',' -k2,2n | head -n 10 | awk -F, '{printf "Endpoint: %s | Avg Delay: %s ms | Packet Loss: %s%%\n", $1, $2, $3}'
    
    echo ""
    if [ -n "$best_ip" ]; then
         echo -e "${green}Best endpoint selected: $best_ip with average delay $best_delay ms${reset}"
         echo "$best_ip" > "$BEST_IPS_FILE"
    else
         echo -e "${red}No valid IP address found.${reset}"
    fi

    echo -ne "${cyan}Run detailed performance tests on $best_ip? (y/n): ${reset}"
    read -r run_tests
    if [[ "$run_tests" =~ ^[Yy]$ ]]; then
         run_all_tests "$best_ip"
    fi

    echo -ne "${cyan}Return to the main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
         main_menu
    fi
}

# ----- Warp Hidify Feature -----
warp_hidify() {
    local ip_type="ipv4"
    if [ "$1" = "ipv6" ]; then
         ip_type="ipv6"
    fi
    local best_ip=""
    if [ -s "$BEST_IPS_FILE" ]; then
         best_ip=$(head -n 1 "$BEST_IPS_FILE")
    else
         inline_scan "$ip_type"
         best_ip=$(head -n 1 "$BEST_IPS_FILE")
    fi
    if [ -z "$best_ip" ]; then
         error_exit "No valid IP found."
    fi
    local warp_uri=""
    if [ "$ip_type" = "ipv4" ]; then
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

# ----- Generate WireGuard Configuration -----
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
                    inline_scan "ipv4"
                    endpoint=$(head -n 1 "$BEST_IPS_FILE")
                    ;;
                2)
                    inline_scan "ipv6"
                    endpoint=$(head -n 1 "$BEST_IPS_FILE")
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
        if [ -z "$config_path" ]; then
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
        
        if [ $? -eq 0 ]; then
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

# ----- Main Menu -----
main_menu() {
    clear
    echo -e "${magenta}Warp IP Scanner & WireGuard Config Generator v$VERSION${reset}"
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
            inline_scan "ipv4"
            ;;
        2)
            inline_scan "ipv6"
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

for cmd in grep sort; do
    if ! command -v "$cmd" &>/dev/null; then
        error_exit "Command $cmd not found. Please install the essential system packages."
    fi
done

main_menu
