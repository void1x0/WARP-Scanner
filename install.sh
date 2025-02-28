#!/bin/bash
# --------------------------------------
#     ACCESS INTERNET WITH WARP
# --------------------------------------
#     Developed: 2025
# --------------------------------------

# Global configuration
APP_VERSION="2.0"
CONFIG_DIR="$HOME/.config/warp-tool"
TEMP_DIR="/tmp/warp-tool-$$"
BIN_PATH="$CONFIG_DIR/scanner"
RESULT_FILE="$TEMP_DIR/endpoints.txt"
CONFIG_FILE="$HOME/warp-config.conf"

# Text styles
txt_b="\e[1m"      # Bold
txt_u="\e[4m"      # Underline
txt_r="\e[0m"      # Reset

# Colors palette
col_1="\e[38;5;51m"    # Cyan
col_2="\e[38;5;201m"   # Magenta
col_3="\e[38;5;46m"    # Green
col_4="\e[38;5;226m"   # Yellow
col_5="\e[38;5;196m"   # Red
col_6="\e[38;5;21m"    # Blue

# Check all required tools
check_requirements() {
    local missing_tools=()
    
    command -v curl >/dev/null 2>&1 || missing_tools+=("curl")
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_message "ERROR" "Required tools are missing: ${missing_tools[*]}"
        print_message "INFO" "Please install the missing tools and try again"
        exit 1
    fi
}

# Initialize environment
init_environment() {
    # Create directories
    mkdir -p "$CONFIG_DIR" "$TEMP_DIR"
    
    # Check requirements
    check_requirements
    
    # Set resource limits
    ulimit -n 102400 >/dev/null 2>&1 || true
}

# Display fancy text
print_fancy_text() {
    local text="$1"
    local width=$((${#text} + 6))
    local border=$(printf "%${width}s" | tr " " "═")
    
    echo -e "${col_2}╔${border}╗"
    echo -e "║   ${col_1}${txt_b}${text}${txt_r}${col_2}   ║"
    echo -e "╚${border}╝${txt_r}"
}

# Display status message
print_message() {
    local type="$1"
    local message="$2"
    
    case "$type" in
        "INFO")     echo -e "${col_1}[${txt_b}i${txt_r}${col_1}] ${message}${txt_r}" ;;
        "SUCCESS")  echo -e "${col_3}[${txt_b}✓${txt_r}${col_3}] ${message}${txt_r}" ;;
        "WARNING")  echo -e "${col_4}[${txt_b}!${txt_r}${col_4}] ${message}${txt_r}" ;;
        "ERROR")    echo -e "${col_5}[${txt_b}✗${txt_r}${col_5}] ${message}${txt_r}" ;;
        "QUESTION") echo -e "${col_6}[${txt_b}?${txt_r}${col_6}] ${message}${txt_r}" ;;
        *)          echo -e "${message}" ;;
    esac
}

# Show loading animation
display_progress() {
    local pid=$1
    local message="${2:-Processing}"
    local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    local delay=0.1
    
    while [ -d /proc/$pid ]; do
        for (( i=0; i<${#chars}; i++ )); do
            echo -ne "${col_3}[${chars:$i:1}]${txt_r} $message\r"
            sleep $delay
        done
    done
    echo -ne "                                        \r"
}

# Obtain scanner tool
obtain_scanner_tool() {
    if [[ ! -f "$BIN_PATH" ]]; then
        print_message "INFO" "Downloading scanner tool..."
        curl -L -o "$BIN_PATH" --retry 3 --silent "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/endip/amd64"
        chmod +x "$BIN_PATH"
        print_message "SUCCESS" "Scanner tool downloaded"
    fi
    
    # Copy to temp directory for execution
    cp -f "$BIN_PATH" "$TEMP_DIR/scanner"
}

# Generate IP pool
generate_ip_pool() {
    local mode="$1"
    local outfile="$TEMP_DIR/ip_pool.txt"
    
    print_message "INFO" "Generating $mode address pool..."
    
    if [[ "$mode" == "ipv4" ]]; then
        # IPv4 address ranges for Cloudflare WARP
        local ipv4_ranges=(
            "162.159.192" "162.159.193" "162.159.194" "162.159.195" 
            "188.114.96" "188.114.97" "188.114.98" "188.114.99" 
            "188.114.100" "188.114.101"
        )
        
        # Generate 100 random IPv4 addresses
        > "$outfile"
        for i in {1..100}; do
            local base=${ipv4_ranges[$RANDOM % ${#ipv4_ranges[@]}]}
            local last=$((RANDOM % 256))
            echo "$base.$last" >> "$outfile"
        done
    else
        # IPv6 address ranges for Cloudflare WARP
        local ipv6_ranges=(
            "2606:4700:d0::" "2606:4700:d1::" "2606:4700:110::"
        )
        
        # Generate 100 random IPv6 addresses
        > "$outfile"
        for i in {1..100}; do
            local base=${ipv6_ranges[$RANDOM % ${#ipv6_ranges[@]}]}
            local hex1=$(printf "%04x" $((RANDOM % 65536)))
            local hex2=$(printf "%04x" $((RANDOM % 65536)))
            local hex3=$(printf "%04x" $((RANDOM % 65536)))
            local hex4=$(printf "%04x" $((RANDOM % 65536)))
            echo "[$base$hex1:$hex2:$hex3:$hex4]" >> "$outfile"
        done
    fi
    
    print_message "SUCCESS" "Generated $(wc -l < "$outfile") addresses"
}

# Scan IP addresses
scan_endpoints() {
    local mode="$1"
    local pool_file="$TEMP_DIR/ip_pool.txt"
    
    # Ensure we have IP pool
    if [[ ! -f "$pool_file" ]]; then
        generate_ip_pool "$mode"
    fi
    
    print_message "INFO" "Starting endpoint scan..."
    
    # Run scanner in background
    cd "$TEMP_DIR"
    ./scanner > /dev/null 2>&1 &
    local scanner_pid=$!
    
    # Show progress animation
    display_progress $scanner_pid "Scanning endpoints"
    
    # Process results
    if [[ -f "$TEMP_DIR/result.csv" ]]; then
        # Convert to readable format and sort by latency
        awk -F, '$3!="timeout ms" {print $1 " | " $3}' "$TEMP_DIR/result.csv" | 
            sort -t'|' -k2 -n > "$RESULT_FILE"
        
        print_message "SUCCESS" "Scan completed with $(wc -l < "$RESULT_FILE") results"
    else
        print_message "ERROR" "Scan failed - no results found"
        return 1
    fi
}

# Display scan results
show_scan_results() {
    local mode="$1"
    
    if [[ ! -f "$RESULT_FILE" || ! -s "$RESULT_FILE" ]]; then
        print_message "ERROR" "No results available"
        return 1
    fi
    
    print_fancy_text "TOP 5 ENDPOINTS"
    
    # Display top 5 results
    local count=0
    while IFS= read -r line && [[ $count -lt 5 ]]; do
        echo -e "${col_4}[$((count+1))]${txt_r} ${col_1}${line}${txt_r}"
        ((count++))
    done < "$RESULT_FILE"
    
    # Extract best endpoint
    if [[ "$mode" == "ipv4" ]]; then
        best_endpoint=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n1)
    else
        best_endpoint=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n1)
    fi
    
    if [[ -n "$best_endpoint" ]]; then
        local latency=$(grep "$best_endpoint" "$RESULT_FILE" | grep -oE "[0-9]+ ms" | head -n1)
        echo
        print_fancy_text "BEST ENDPOINT"
        echo -e "${col_3}${txt_b}$best_endpoint${txt_r}"
        echo -e "${col_1}Latency: ${col_3}$latency${txt_r}"
    fi
}

# Check and install WireGuard tools
install_wireguard() {
    if command -v wg &>/dev/null; then
        print_message "INFO" "WireGuard is already installed"
        return 0
    fi
    
    print_message "WARNING" "WireGuard tools not installed. Attempting to install..."
    
    # Detect operating system
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        print_message "INFO" "Detected Debian/Ubuntu system"
        print_message "INFO" "Running: sudo apt update && sudo apt install -y wireguard-tools"
        sudo apt update && sudo apt install -y wireguard-tools
    elif [ -f /etc/fedora-release ]; then
        # Fedora
        print_message "INFO" "Detected Fedora system"
        print_message "INFO" "Running: sudo dnf install -y wireguard-tools"
        sudo dnf install -y wireguard-tools
    elif [ -f /etc/arch-release ]; then
        # Arch Linux
        print_message "INFO" "Detected Arch Linux system"
        print_message "INFO" "Running: sudo pacman -S --noconfirm wireguard-tools"
        sudo pacman -S --noconfirm wireguard-tools
    else
        print_message "ERROR" "Could not detect package manager. Please install WireGuard tools manually."
        print_message "INFO" "Installation commands for different systems:"
        echo -e "${col_1}Debian/Ubuntu:${txt_r} sudo apt update && sudo apt install -y wireguard-tools"
        echo -e "${col_1}Fedora:${txt_r} sudo dnf install -y wireguard-tools"
        echo -e "${col_1}Arch Linux:${txt_r} sudo pacman -S wireguard-tools"
        echo -e "${col_1}macOS:${txt_r} brew install wireguard-tools"
        return 1
    fi
    
    # Check if installation was successful
    if command -v wg &>/dev/null; then
        print_message "SUCCESS" "WireGuard tools installed successfully"
        return 0
    else
        print_message "ERROR" "Failed to install WireGuard tools"
        return 1
    fi
}

# Generate encryption keys with specific format
generate_keys() {
    if ! command -v wg &>/dev/null; then
        print_message "WARNING" "WireGuard tools not installed"
        install_wireguard || return 1
    fi
    
    print_message "INFO" "Generating encryption keys..."
    
    # Generate the raw keys
    local raw_private=$(wg genkey)
    local raw_public=$(echo "$raw_private" | wg pubkey)
    
    # Format the private key according to the template (2IhVcDH9iXXXXXXXXXXXXXXXXXX)
    local private_prefix=${raw_private:0:8}
    local private_formatted="${private_prefix}XXXXXXXXXXXXXXXXXXXXXXX"
    
    # Format the public key according to the template (bmXOC+XXXXXXXXXXXXXXXXXXXXXX)
    local public_prefix=${raw_public:0:6}
    local public_formatted="${public_prefix}XXXXXXXXXXXXXXXXXXXXXX"
    
    echo "$private_formatted:$public_formatted"
}

# Create WireGuard configuration
create_wireguard_config() {
    local endpoint="$1"
    
    if [[ -z "$endpoint" ]]; then
        # Ask user for endpoint choice
        print_message "QUESTION" "Select endpoint source:"
        echo -e "${col_4}[1]${txt_r} Scan for fastest endpoint"
        echo -e "${col_4}[2]${txt_r} Use default endpoint"
        read -p "Choice: " choice
        
        case "$choice" in
            1)
                print_message "QUESTION" "Select IP version:"
                echo -e "${col_4}[1]${txt_r} IPv4"
                echo -e "${col_4}[2]${txt_r} IPv6"
                read -p "Choice: " ip_ver
                
                if [[ "$ip_ver" == "1" ]]; then
                    scan_endpoints "ipv4"
                    endpoint=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n1)
                elif [[ "$ip_ver" == "2" ]]; then
                    scan_endpoints "ipv6"
                    endpoint=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n1)
                else
                    print_message "WARNING" "Invalid choice, using default"
                    endpoint="engage.cloudflareclient.com:2408"
                fi
                ;;
            2)
                print_message "QUESTION" "Select default endpoint:"
                echo -e "${col_4}[1]${txt_r} engage.cloudflareclient.com:2408"
                echo -e "${col_4}[2]${txt_r} engage.cloudflareclient.com:2409"
                read -p "Choice: " def_ep
                
                if [[ "$def_ep" == "1" ]]; then
                    endpoint="engage.cloudflareclient.com:2408"
                elif [[ "$def_ep" == "2" ]]; then
                    endpoint="engage.cloudflareclient.com:2409"
                else
                    print_message "WARNING" "Invalid choice, using default"
                    endpoint="engage.cloudflareclient.com:2408"
                fi
                ;;
            *)
                print_message "WARNING" "Invalid choice, using default"
                endpoint="engage.cloudflareclient.com:2408"
                ;;
        esac
    fi
    
    # Generate keys
    local key_pair=$(generate_keys)
    local private_key=${key_pair%%:*}
    local public_key=${key_pair##*:}
    
    print_message "INFO" "Creating WireGuard configuration..."
    
    # Create config file
    cat > "$CONFIG_FILE" <<EOC
[Interface]
PrivateKey = $private_key
Address = 172.16.0.2/32, 2606:4700:110:848e:fec7:926a:f8d:1ca/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = $public_key
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $endpoint
EOC
    
    print_message "SUCCESS" "Configuration saved to $CONFIG_FILE"
    
    # Display summary
    print_fancy_text "WIREGUARD DETAILS"
    echo -e "${col_1}Private Key:${txt_r} ${txt_b}$private_key${txt_r}"
    echo -e "${col_1}Public Key:${txt_r} ${txt_b}$public_key${txt_r}"
    echo -e "${col_1}Endpoint:${txt_r} ${txt_b}$endpoint${txt_r}"
}

# Create WHA (Warp Hiddify App) link
create_wha_link() {
    print_message "QUESTION" "Select IP version for WHA link:"
    echo -e "${col_4}[1]${txt_r} IPv4"
    echo -e "${col_4}[2]${txt_r} IPv6"
    read -p "Choice: " ip_ver
    
    local mode=""
    if [[ "$ip_ver" == "1" ]]; then
        mode="ipv4"
    elif [[ "$ip_ver" == "2" ]]; then
        mode="ipv6"
    else
        print_message "ERROR" "Invalid choice"
        return 1
    fi
    
    # Scan endpoints
    scan_endpoints "$mode"
    show_scan_results "$mode"
    
    # Get best endpoint
    local endpoint=""
    if [[ "$mode" == "ipv4" ]]; then
        endpoint=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" "$RESULT_FILE" | head -n1)
    else
        endpoint=$(grep -oE "\[.*\]:[0-9]+" "$RESULT_FILE" | head -n1)
    fi
    
    if [[ -n "$endpoint" ]]; then
        local wha_link="warp://$endpoint/?ifp=5-10@void1x0"
        
        print_fancy_text "WHA LINK"
        echo -e "${col_3}${txt_b}$wha_link${txt_r}"
        echo -e "${col_1}Ready to use with Warp Hiddify App${txt_r}"
    else
        print_message "ERROR" "No valid endpoint found for WHA link"
    fi
}

# Clean up temporary files
cleanup() {
    print_message "INFO" "Cleaning up..."
    rm -rf "$TEMP_DIR"
}

# Display main menu
show_menu() {
    clear
    print_fancy_text "ACCESS INTERNET WITH WARP v$APP_VERSION"
    echo
    echo -e "${col_4}[1]${txt_r} Scan IPv4 Endpoints"
    echo -e "${col_4}[2]${txt_r} Scan IPv6 Endpoints"
    echo -e "${col_4}[3]${txt_r} Generate WireGuard Config"
    echo -e "${col_4}[4]${txt_r} Create WHA Link"
    echo -e "${col_4}[0]${txt_r} Exit"
    echo
    echo -ne "${col_6}Select option:${txt_r} "
}

# Main program
main() {
    # Setup environment
    init_environment
    obtain_scanner_tool
    
    # Register cleanup
    trap cleanup EXIT
    
    # Main program loop
    while true; do
        show_menu
        read choice
        
        case "$choice" in
            1)
                clear
                generate_ip_pool "ipv4"
                scan_endpoints "ipv4"
                show_scan_results "ipv4"
                ;;
            2)
                clear
                generate_ip_pool "ipv6"
                scan_endpoints "ipv6"
                show_scan_results "ipv6"
                ;;
            3)
                clear
                create_wireguard_config
                ;;
            4)
                clear
                create_wha_link
                ;;
            0)
                print_message "SUCCESS" "Thanks for using WARP Tool!"
                exit 0
                ;;
            *)
                print_message "ERROR" "Invalid option"
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

# Start program
main
