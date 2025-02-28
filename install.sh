#!/bin/bash
# Warp IP Scanner & WireGuard Config Generator

VERSION="1.0"

# Color definitions (using 256-color codes)
red='\033[38;5;196m'
green='\033[38;5;82m'
yellow='\033[38;5;208m'
blue='\033[38;5;27m'
magenta='\033[38;5;201m'
cyan='\033[38;5;117m'
reset='\033[0m'

# Cleanup function for temp files
cleanup() {
    echo -e "${blue}Cleaning up temporary files...${reset}"
    rm -f ip.txt temp_* best_ips.txt
    # Keep result.txt and wg-config.conf for user reference
}
trap cleanup EXIT INT TERM

# Check for updates
check_update() {
    echo -e "${cyan}Checking for updates...${reset}"
    local latest_version
    latest_version=$(curl -s "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/version.txt" 2>/dev/null || echo "$VERSION")
    
    if [[ "$latest_version" != "$VERSION" && "$latest_version" != "" ]]; then
        echo -e "${yellow}Visit https://github.com/void1x0/WARP-Scanner for updates.${reset}"
    else
        echo -e "${green}You are using the latest version ($VERSION).${reset}"
    fi
}

# Download warpendpoint if not available in the current directory
download_warpendpoint() {
    if [[ ! -f "./warpendpoint" ]]; then
        echo -e "${cyan}Downloading warpendpoint...${reset}"
        # Assumes amd64 architecture; modify URL if needed.
        curl -L -o warpendpoint -# --retry 2 "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/endip/amd64"
        chmod +x warpendpoint
    fi
}

# Generate 100 unique IPv4 addresses from extended Warp bases
generate_ipv4() {
    local total=100
    # Extended list of IPv4 bases from Warp
    local bases=("162.159.192" "162.159.193" "162.159.194" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99" "188.114.100" "188.114.101")
    ipv4_list=()
    while [ "$(printf "%s\n" "${ipv4_list[@]}" | sort -u | wc -l)" -lt "$total" ]; do
        idx=$(( RANDOM % ${#bases[@]} ))
        ip="${bases[$idx]}.$(( RANDOM % 256 ))"
        if ! printf "%s\n" "${ipv4_list[@]}" | grep -qx "$ip"; then
            ipv4_list+=("$ip")
        fi
    done
}

# Generate 100 unique IPv6 addresses from extended Warp bases
generate_ipv6() {
    local total=100
    # Extended list of IPv6 bases
    local bases=("2606:4700:d0::" "2606:4700:d1::" "2606:4700:110::")
    ipv6_list=()
    rand_hex() {
        printf '%x' $(( RANDOM % 65536 ))
    }
    while [ "$(printf "%s\n" "${ipv6_list[@]}" | sort -u | wc -l)" -lt "$total" ]; do
        idx=$(( RANDOM % ${#bases[@]} ))
        seg1=$(rand_hex)
        seg2=$(rand_hex)
        seg3=$(rand_hex)
        seg4=$(rand_hex)
        ip="[${bases[$idx]}${seg1}:${seg2}:${seg3}:${seg4}]"
        if ! printf "%s\n" "${ipv6_list[@]}" | grep -qx "$ip"; then
            ipv6_list+=("$ip")
        fi
    done
}

# Function to convert CSV to TXT format
convert_csv_to_txt() {
    if [[ -f result.csv ]]; then
        awk -F, '$3!="timeout ms" {print "Endpoint: "$1" | Delay: "$3}' result.csv | sort -t, -nk3 | uniq > result.txt
        rm -f result.csv
    fi
}

# Run warpendpoint scan and display results.
# Expects parameter "ipv4" or "ipv6" to know which IP list to use.
scan_results() {
    if [ "$1" == "ipv4" ]; then
        printf "%s\n" "${ipv4_list[@]}" | sort -u > ip.txt
    elif [ "$1" == "ipv6" ]; then
        printf "%s\n" "${ipv6_list[@]}" | sort -u > ip.txt
    fi

    ulimit -n 102400
    chmod +x warpendpoint >/dev/null 2>&1
    if [[ -x "./warpendpoint" ]]; then
        ./warpendpoint
        convert_csv_to_txt
    else
        echo -e "${red}warpendpoint not found or not executable.${reset}"
        exit 1
    fi

    clear
    if [[ -f result.txt ]]; then
        echo -e "${magenta}Scan Results:${reset}"
        cat result.txt | head -n 11
        best_ipv4=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" result.txt | head -n 1)
        best_ipv6=$(grep -oE "\[.*\]:[0-9]+" result.txt | head -n 1)
        delay=$(grep -oE "[0-9]+ ms|timeout" result.txt | head -n 1)
        echo ""
        echo -e "${green}Results saved in result.txt${reset}"
        echo ""
        if [[ "$1" == "ipv4" && -n "$best_ipv4" ]]; then
            echo -e "${magenta}******** Best IPv4 ********${reset}"
            echo -e "${blue}$best_ipv4${reset}"
            echo -e "${blue}Delay: ${green}[$delay]${reset}"
        elif [[ "$1" == "ipv6" && -n "$best_ipv6" ]]; then
            echo -e "${magenta}******** Recommended IPv6 ********${reset}"
            echo -e "${blue}$best_ipv6${reset}"
            echo -e "${blue}Delay: ${green}[$delay]${reset}"
        else
            echo -e "${red}No valid IP found.${reset}"
        fi
    else
        echo -e "${red}result.txt not found. Scan may have failed.${reset}"
    fi
}

# Generate a WireGuard configuration file with new keys.
# Optionally performs an IP scan to determine the best endpoint.
generate_wg_config() {
    echo -ne "${cyan}Generate WireGuard configuration? (y/n): ${reset}"
    read -r resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
        echo -ne "${cyan}Perform IP scan for endpoint? (y/n): ${reset}"
        read -r scan_choice
        if [[ "$scan_choice" =~ ^[Yy]$ ]]; then
            echo -ne "${cyan}Select IP version for scan: [1] IPv4, [2] IPv6: ${reset}"
            read -r ip_choice
            case "$ip_choice" in
                1)
                    download_warpendpoint
                    generate_ipv4
                    scan_results "ipv4"
                    endpoint=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" result.txt | head -n 1)
                    ;;
                2)
                    download_warpendpoint
                    generate_ipv6
                    scan_results "ipv6"
                    endpoint=$(grep -oE "\[.*\]:[0-9]+" result.txt | head -n 1)
                    ;;
                *)
                    echo -e "${yellow}Invalid choice. Using default endpoint.${reset}"
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
                    echo -e "${yellow}Invalid choice. Using default endpoint.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        fi

        # Generate new WireGuard keys
        if command -v wg &>/dev/null; then
            private_key=$(wg genkey)
            public_key=$(echo "$private_key" | wg pubkey)
        else
            echo -e "${red}wireguard-tools not installed. Please install wg.${reset}"
            exit 1
        fi

        # Default WireGuard client addresses per sample config
        wg_ipv4="172.16.0.2/32"
        wg_ipv6="2606:4700:110:848e:fec7:926a:f8d:1ca/128"

        config_path="/storage/emulated/0/wg-config.conf"
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

        echo -e "${green}WireGuard configuration generated and saved to $config_path${reset}"
        echo -e "${magenta}Configuration Details:${reset}"
        echo -e "${cyan}Private Key: ${green}$private_key${reset}"
        echo -e "${cyan}Public Key: ${green}$public_key${reset}"
        echo -e "${cyan}IPv4 Address: ${green}$wg_ipv4${reset}"
        echo -e "${cyan}IPv6 Address: ${green}$wg_ipv6${reset}"
        echo -e "${cyan}Endpoint: ${green}$endpoint${reset}"
        echo -e "${cyan}DNS: ${green}1.1.1.1, 1.0.0.1${reset}"
        echo -e "${cyan}MTU: ${green}1280${reset}"
    else
        echo -e "${yellow}WireGuard configuration generation skipped.${reset}"
    fi
}

# ----- WHA (Warp Hiddify App) Function -----

warp_hiddify() {
    local ip_type="ipv4"
    if [[ "$1" == "6" ]]; then
        ip_type="ipv6"
    fi
    
    # Generate and scan IPs to find clean ones
    echo -e "${magenta}Scanning for clean ${ip_type} IPs for Warp Hiddify App...${reset}"
    download_warpendpoint
    
    if [[ "$ip_type" == "ipv4" ]]; then
        generate_ipv4
    else
        generate_ipv6
    fi
    
    # Perform scan
    ulimit -n 102400 2>/dev/null || ulimit -n 4096 2>/dev/null || true
    chmod +x warpendpoint >/dev/null 2>&1
    if [[ -x "./warpendpoint" ]]; then
        ./warpendpoint
        convert_csv_to_txt
    else
        echo -e "${red}warpendpoint not found or not executable.${reset}"
        exit 1
    fi
    
    # Get the best IP
    local best_ip=""
    if [[ "$ip_type" == "ipv4" ]]; then
        best_ip=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" result.txt | head -n 1)
    else
        best_ip=$(grep -oE "\[.*\]" result.txt | head -n 1 | tr -d '[]')
    fi
    
    if [[ -z "$best_ip" ]]; then
        echo -e "${red}No valid IP found. Try again.${reset}"
        return
    fi
    
    # Generate Warp Hiddify URI
    local warp_uri=""
    if [[ "$ip_type" == "ipv4" ]]; then
        local port=1843
        warp_uri="warp://$best_ip:$port/?ifp=5-10@void1x0"
    else
        local port=878
        warp_uri="warp://[$best_ip]:$port/?ifp=5-10@void1x0"
    fi
    
    echo -e "${green}Warp Hiddify URI generated:${reset}"
    echo -e "${blue}$warp_uri${reset}"
    echo ""
    
    # Save to file
    echo "$warp_uri" > "warp_hiddify.txt"
    echo -e "${green}URI saved to warp_hiddify.txt${reset}"
}

# Main menu
clear
echo -e "${magenta}Warp IP Scanner & WireGuard Config Generator v$VERSION${reset}"
check_update
echo -e "${blue}Select an option:${reset}"
echo -e "${yellow}[1] Scan IPv4${reset}"
echo -e "${yellow}[2] Scan IPv6${reset}"
echo -e "${yellow}[3] Generate WireGuard Config${reset}"
echo -e "${yellow}[4] WHA (Warp Hiddify App)${reset}"
echo -e "${yellow}[0] Exit${reset}"
echo -ne "${cyan}Your choice: ${reset}"
read -r choice
case "$choice" in
    1)
        download_warpendpoint
        generate_ipv4
        scan_results "ipv4"
        ;;
    2)
        download_warpendpoint
        generate_ipv6
        scan_results "ipv6"
        ;;
    3)
        generate_wg_config
        ;;
    4)
        echo -e "${cyan}Choose IP version for Warp Hiddify App:${reset}"
        echo -e "${yellow}[1] IPv4${reset}"
        echo -e "${yellow}[2] IPv6${reset}"
        echo -ne "${cyan}Your choice: ${reset}"
        read -r wha_choice
        case "$wha_choice" in
            1)
                warp_hiddify "4"
                ;;
            2)
                warp_hiddify "6"
                ;;
            *)
                echo -e "${red}Invalid choice. Using IPv4.${reset}"
                warp_hiddify "4"
                ;;
        esac
        ;;
    0)
        echo -e "${green}Exiting...${reset}"
        exit 0
        ;;
    *)
        echo -e "${red}Invalid choice.${reset}"
        exit 1
        ;;
esac
