
#!/bin/bash
# Access Internet with WARP - Scanner & Config Generator

VERSION="1.0"

# Color definitions (using 256-color codes)
red='\033[38;5;196m'
green='\033[38;5;82m'
yellow='\033[38;5;208m'
blue='\033[38;5;27m'
magenta='\033[38;5;201m'
cyan='\033[38;5;117m'
reset='\033[0m'

# ASCII Art Banner
display_banner() {
    clear
    echo -e "${blue}╔══════════════════════════════════════════════════╗${reset}"
    echo -e "${blue}║                                                  ║${reset}"
    echo -e "${blue}║${magenta}       ACCESS INTERNET WITH WARP v$VERSION${blue}          ║${reset}"
    echo -e "${blue}║${cyan}          Fast & Secure Connection${blue}                ║${reset}"
    echo -e "${blue}║                                                  ║${reset}"
    echo -e "${blue}╚══════════════════════════════════════════════════╝${reset}"
    echo ""
}

# Cleanup function for temp files
cleanup() {
    echo -e "${blue}Cleaning up temporary files...${reset}"
    rm -f ip.txt temp_* best_ips.txt
    # Keep result.txt and wg-config.conf for user reference
}
trap cleanup EXIT INT TERM

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

    # Check if IPv6 is supported
    if ! ping -6 -c 1 2606:4700:4700::1111 &>/dev/null; then
        echo -e "${red}Warning: IPv6 connectivity not available in this environment.${reset}"
        echo -e "${yellow}Replit does not support IPv6 scanning. Please use IPv4 option instead.${reset}"
        return 1
    fi
}

# Function to convert CSV to TXT format
convert_csv_to_txt() {
    if [[ -f result.csv ]]; then
        awk -F, '$3!="timeout ms" {print "Endpoint: "$1" | Delay: "$3}' result.csv | sort -t, -nk3 | uniq > result.txt
        rm -f result.csv
    fi
}

# Show loading animation
show_loading() {
    local pid=$1
    local spin='-\|/'
    local i=0
    echo -e "${cyan}Scanning Warp endpoints...${reset}"
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${green}[%c]${reset} ${blue}Testing endpoints, please wait...${reset}" "${spin:$i:1}"
        sleep 0.1
    done
    printf "\r${green}[✓]${reset} ${blue}Scan completed!                   ${reset}\n"
}

# Run warpendpoint scan and display results.
# Expects parameter "ipv4" or "ipv6" to know which IP list to use.
scan_results() {
    if [ "$1" == "ipv4" ]; then
        printf "%s\n" "${ipv4_list[@]}" | sort -u > ip.txt
    elif [ "$1" == "ipv6" ]; then
        # Check if IPv6 is available
        if ! ping -6 -c 1 2606:4700:4700::1111 &>/dev/null; then
            echo -e "${red}ERROR: IPv6 connectivity not available in Replit environment.${reset}"
            echo -e "${yellow}Please use the IPv4 option instead.${reset}"
            return 1
        fi
        printf "%s\n" "${ipv6_list[@]}" | sort -u > ip.txt
    fi

    ulimit -n 102400
    chmod +x warpendpoint >/dev/null 2>&1
    if [[ -x "./warpendpoint" ]]; then
        # Run warpendpoint in the background with output redirected
        ./warpendpoint > /tmp/warp_scan_output.log 2>&1 &
        local scan_pid=$!
        
        # Show loading animation while scanning
        show_loading $scan_pid
        
        # Wait for scan to complete
        wait $scan_pid
        
        # Process the results
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
            echo -e "${cyan}Select IP version for scan:${reset}"
            echo -e "${yellow}[1] IPv4${reset}"
            echo -e "${yellow}[2] IPv6 ${red}(Not supported in Replit)${reset}"
            echo -ne "${cyan}Your choice: ${reset}"
            read -r ip_choice
            case "$ip_choice" in
                1)
                    download_warpendpoint
                    generate_ipv4
                    scan_results "ipv4"
                    endpoint=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" result.txt | head -n 1)
                    if [[ -z "$endpoint" ]]; then
                        echo -e "${yellow}No valid endpoint found. Using default.${reset}"
                        endpoint="engage.cloudflareclient.com:2408"
                    fi
                    ;;
                2)
                    echo -e "${red}WARNING: IPv6 is not supported in Replit environment.${reset}"
                    echo -e "${yellow}Using default endpoint instead.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
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

# Generate Warp link for Hiddify App
generate_wha_link() {
    echo -e "${cyan}Generating Warp link for Hiddify App...${reset}"
    echo -e "${yellow}NOTE: IPv6 is not supported in Replit environment${reset}"
    echo -ne "${cyan}Select IP version for scan: [1] IPv4, [2] IPv6 (Not recommended): ${reset}"
    read -r ip_choice
    
    case "$ip_choice" in
        1)
            download_warpendpoint
            generate_ipv4
            scan_results "ipv4"
            if [[ -n "$best_ipv4" ]]; then
                ip_port=$best_ipv4
                ip=${ip_port%:*}
                port=${ip_port#*:}
                echo -e "${green}Generated WHA Link:${reset}"
                echo -e "${magenta}warp://${ip}:${port}/?ifp=5-10@void1x0${reset}"
                echo -e "${blue}Copy and use this link in Hiddify App${reset}"
            else
                echo -e "${red}No valid IPv4 found.${reset}"
                echo -e "${yellow}Using default endpoint: engage.cloudflareclient.com:2408${reset}"
                echo -e "${green}Generated WHA Link:${reset}"
                echo -e "${magenta}warp://engage.cloudflareclient.com:2408/?ifp=5-10@void1x0${reset}"
            fi
            ;;
        2)
            echo -e "${red}WARNING: IPv6 is not supported in Replit environment.${reset}"
            echo -e "${yellow}Using default endpoint instead.${reset}"
            echo -e "${green}Generated WHA Link:${reset}"
            echo -e "${magenta}warp://engage.cloudflareclient.com:2408/?ifp=5-10@void1x0${reset}"
            echo -e "${blue}Copy and use this link in Hiddify App${reset}"
            ;;
        *)
            echo -e "${red}Invalid choice.${reset}"
            echo -e "${yellow}Using default endpoint: engage.cloudflareclient.com:2408${reset}"
            echo -e "${green}Generated WHA Link:${reset}"
            echo -e "${magenta}warp://engage.cloudflareclient.com:2408/?ifp=5-10@void1x0${reset}"
            ;;
    esac
}

# Main menu
display_banner
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
        generate_wha_link
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
