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

for cmd in bc dig curl sed awk sort ping; do
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

# ----- Colors and Version -----
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

VERSION="1.2 (Inline Scan)"

# ----- Inline IP Generation Functions -----
generate_ipv4_inline() {
    local total=100
    local bases=("162.159.192" "162.159.193" "162.159.194" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99" "188.114.100" "188.114.101")
    declare -A ip_set=()
    local count=0
    local ip_list=()
    while [ $count -lt $total ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local ip="${bases[$idx]}.$(( RANDOM % 256 ))"
        if [[ -z "${ip_set[$ip]}" ]]; then
            ip_set["$ip"]=1
            ip_list+=("$ip")
            count=$((count+1))
        fi
    done
    printf "%s\n" "${ip_list[@]}"
}

generate_ipv6_inline() {
    local total=100
    local bases=("2606:4700:d0::" "2606:4700:d1::" "2606:4700:110::")
    declare -A ip_set=()
    local count=0
    local ip_list=()
    rand_hex() {
        printf '%x' $(( RANDOM % 65536 ))
    }
    while [ $count -lt $total ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local seg1=$(rand_hex)
        local seg2=$(rand_hex)
        local seg3=$(rand_hex)
        local seg4=$(rand_hex)
        local ip="[${bases[$idx]}${seg1}:${seg2}:${seg3}:${seg4}]"
        if [[ -z "${ip_set[$ip]}" ]]; then
            ip_set["$ip"]=1
            ip_list+=("$ip")
            count=$((count+1))
        fi
    done
    printf "%s\n" "${ip_list[@]}"
}

# ----- Performance Test Functions -----
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

run_all_tests() {
    local ip="$1"
    echo -e "${magenta}Running detailed performance tests for IP: $ip${reset}"
    
    echo -e "${cyan}Bandwidth Test (not implemented inline, skipping)...${reset}"
    echo -e "${cyan}Stability Test (Average, Jitter, Packet Loss):${reset}"
    stability_result=$(test_stability "$ip")
    echo -e "${blue}$stability_result${reset}"
    
    echo -e "${cyan}Optimal MTU Test (using ping test):${reset}"
    local start_mtu=1500
    local min_mtu=576
    local best_mtu=$start_mtu
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
    echo -e "${blue}Optimal MTU: $best_mtu${reset}"
    
    echo -e "${cyan}DNS Leak Test (not implemented inline)...${reset}"
    echo -e "${cyan}GeoIP Info (using ipinfo.io):${reset}"
    local geo_data=$(curl -s "https://ipinfo.io/$ip/json")
    local country=$(echo "$geo_data" | grep -oP '"country": "\K[^"]+')
    local region=$(echo "$geo_data" | grep -oP '"region": "\K[^"]+')
    local city=$(echo "$geo_data" | grep -oP '"city": "\K[^"]+')
    echo -e "${blue}GeoIP info for $ip: Country: $country, Region: $region, City: $city${reset}"
}

# ----- New Inline Scanning Method -----
new_scan() {
    local ip_type="$1"
    local ips=()
    if [[ "$ip_type" == "ipv4" ]]; then
         echo -e "${blue}Generating IPv4 addresses...${reset}"
         mapfile -t ips < <(generate_ipv4_inline)
    else
         echo -e "${blue}Generating IPv6 addresses...${reset}"
         mapfile -t ips < <(generate_ipv6_inline)
    fi

    declare -a results
    echo -e "${blue}Performing stability tests on generated IPs...${reset}"
    for ip in "${ips[@]}"; do
         result=$(test_stability "$ip")  # returns avg,jitter,packet_loss
         avg=$(echo "$result" | cut -d',' -f1)
         packet_loss=$(echo "$result" | cut -d',' -f3)
         results+=("$ip,$avg,$packet_loss")
    done

    # Sort results by average delay (ascending) and take top 10
    sorted_results=$(printf "%s\n" "${results[@]}" | sort -t',' -k2,2n | head -n 10)
    echo -e "${blue}Scan results (Top 10 by average delay):${reset}"
    printf "%s\n" "$sorted_results" | awk -F, '{printf "Endpoint: %s | Average Delay: %s ms | Packet Loss: %s%%\n", $1, $2, $3}'

    best_ip=$(printf "%s\n" "$sorted_results" | head -n 1 | cut -d',' -f1)
    best_avg=$(printf "%s\n" "$sorted_results" | head -n 1 | cut -d',' -f2)
    echo -e "${green}Best endpoint selected: $best_ip with average delay $best_avg ms${reset}"

    echo -ne "${cyan}Run detailed performance tests on $best_ip? (y/n): ${reset}"
    read -r run_tests
    if [[ "$run_tests" =~ ^[Yy]$ ]]; then
         run_all_tests "$best_ip"
    fi

    echo -ne "${cyan}Return to main menu? (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
         main_menu
    fi
}

# ----- WireGuard Config Generation (unchanged) -----
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
                    new_scan "ipv4"
                    endpoint=$(printf "%s\n" "$best_ip")
                    ;;
                2)
                    new_scan "ipv6"
                    endpoint=$(printf "%s\n" "$best_ip")
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

        if ! command -v wg &>/dev/null; then
            error_exit "wireguard-tools not installed. Please install wg."
        fi

        keys=$(wg genkey | { read -r pk; echo "$pk"; } | { echo "$pk" | wg pubkey; } 2>/dev/null)
        # For demonstration, generate keys separately:
        private_key=$(wg genkey)
        public_key=$(echo "$private_key" | wg pubkey)

        local wg_ipv4="172.16.0.2/32"
        local wg_ipv6="2606:4700:110:848e:fec7:926a:f8d:1ca/128"

        echo -ne "${cyan}Enter config file path (default: \$HOME/wg-config.conf): ${reset}"
        read -r config_path
        if [[ -z "$config_path" ]]; then
            config_path="$HOME/wg-config.conf"
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

# ----- Warp Hidify Feature (unchanged) -----
warp_hidify() {
    local ip_type="ipv4"
    if [[ "$1" == "6" ]]; then
         ip_type="ipv6"
    fi
    local best_ip=""
    echo -e "${magenta}Scanning for clean ${ip_type} IPs...${reset}"
    new_scan "$ip_type"
    best_ip="$best_ip"
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
    echo -e "${green}Warp Hidify URI generated:${reset}"
    echo "$warp_uri"

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
            new_scan "ipv4"
            ;;
        2)
            new_scan "ipv6"
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

# Start program
main_menu
