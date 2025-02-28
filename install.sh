#!/bin/bash

# WARP Scanner v1.0.0
# Improved version with WHA support

# Colors
RED='\033[1;31m'      # Brighter red
GREEN='\033[1;32m'    # Brighter green
YELLOW='\033[1;33m'   # Brighter yellow
BLUE='\033[1;34m'     # Brighter blue
PURPLE='\033[1;35m'   # Brighter purple
CYAN='\033[1;36m'     # Brighter cyan
WHITE='\033[1;37m'    # Bright white
NC='\033[0m'          # No Color

# Version
VERSION="1.0.0"

# Loading animation
show_loading() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " %c  Scanning endpoints..." "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        echo -en "\r"
        sleep $delay
    done
    echo -en "\r"
}

# ASCII Art Header
print_header() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${PURPLE}           WARP SCANNER          ${BLUE}║${NC}"
    echo -e "${BLUE}║${CYAN}               Version ${VERSION}              ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo -e "${PURPLE}              By: void1x0${NC}\n"
}

# Check CPU architecture
check_cpu() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64)
            cpu=amd64
            ;;
        i386 | i686)
            cpu=386
            ;;
        armv8 | armv8l | arm64 | aarch64)
            cpu=arm64
            ;;
        armv7l)
            cpu=arm
            ;;
        *)
            echo -e "${RED}Error: Architecture $(uname -m) not supported${NC}"
            exit 1
            ;;
    esac
}

# Download warpendpoint if needed
setup_warpendpoint() {
    if [[ ! -f "$PREFIX/bin/warpendpoint" ]]; then
        echo -e "${CYAN}Downloading warpendpoint program...${NC}"
        if [[ -n $cpu ]]; then
            curl -L -o warpendpoint -# --retry 2 "https://raw.githubusercontent.com/void1x0/warp/main/endip/$cpu"
            cp warpendpoint $PREFIX/bin
            chmod +x $PREFIX/bin/warpendpoint
        fi
    fi
}

# Generate IPv4 endpoints
generate_ipv4() {
    n=0
    iplist=100
    while [ $n -lt $iplist ]; do
        temp[$n]=$(echo "162.159.192.$(($RANDOM % 256))")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "162.159.193.$(($RANDOM % 256))")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "162.159.195.$(($RANDOM % 256))")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "188.114.96.$(($RANDOM % 256))")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "188.114.97.$(($RANDOM % 256))")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "188.114.98.$(($RANDOM % 256))")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "188.114.99.$(($RANDOM % 256))")
        n=$(($n + 1))
    done
}

# Generate IPv6 endpoints
generate_ipv6() {
    n=0
    iplist=100
    while [ $n -lt $iplist ]; do
        temp[$n]=$(echo "[2606:4700:d0::$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2))):$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2))):$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2))):$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2)))]")
        n=$(($n + 1))
        [ $n -ge $iplist ] && break
        temp[$n]=$(echo "[2606:4700:d1::$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2))):$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2))):$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2))):$(printf '%x\n' $(($RANDOM * 2 + $RANDOM % 2)))]")
        n=$(($n + 1))
    done
}

# Process and display results
process_results() {
    echo "${temp[@]}" | sed -e 's/ /\n/g' | sort -u > ip.txt
    ulimit -n 102400
    chmod +x warpendpoint >/dev/null 2>&1

    # Show loading animation while scanning
    warpendpoint & 
    show_loading $!
    wait

    clear
    echo -e "${BLUE}╔═════════════ SCAN RESULTS ═════════════╗${NC}"
    cat result.csv | awk -F, '$3!="timeout ms" {print} ' | sort -t, -nk2 -nk3 | uniq | head -11 | \
        awk -F, '{printf "║ %-35s Delay: %-8s ║\n", $1, $3}'
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}\n"

    best_ip=$(cat result.csv | awk -F, 'NR==2 {print $1}')
    delay=$(cat result.csv | grep -oE "[0-9]+ ms|timeout" | head -n 1)

    # Generate WHA URL
    wha_url="warp://${best_ip}/?ifp=5-10@void1x0"

    echo -e "${GREEN}Best Endpoint Found:${NC}"
    echo -e "${CYAN}$best_ip${NC}"
    echo -e "${YELLOW}Delay: $delay${NC}\n"

    echo -e "${GREEN}Warp Hiddify App (WHA) URL:${NC}"
    echo -e "${CYAN}$wha_url${NC}\n"

    # Cleanup
    rm -f warpendpoint ip.txt 2>/dev/null
}

# Main menu
show_menu() {
    echo -e "${BLUE}╔═════════════ SELECT MODE ════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${GREEN}1${NC}. Scan for IPv4 Endpoints          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${GREEN}2${NC}. Scan for IPv6 Endpoints          ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC} ${RED}0${NC}. Exit                             ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
    echo -en "${CYAN}Enter your choice: ${NC}"
}

# Main execution
main() {
    print_header
    check_cpu
    setup_warpendpoint

    while true; do
        show_menu
        read -r choice

        case "$choice" in
            1)
                echo -e "\n${CYAN}Starting IPv4 endpoint scan...${NC}"
                generate_ipv4
                process_results
                ;;
            2)
                echo -e "\n${CYAN}Starting IPv6 endpoint scan...${NC}"
                generate_ipv6
                process_results
                ;;
            0)
                echo -e "\n${GREEN}Thank you for using WARP Scanner Enhanced!${NC}"
                exit 0
                ;;
            *)
                echo -e "\n${RED}Invalid choice. Please try again.${NC}"
                ;;
        esac
    done
}

# Start the application
main
