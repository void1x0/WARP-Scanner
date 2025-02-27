#!/bin/bash

# تعریف رنگ‌های زیبا (استفاده از 256 رنگ)
red='\033[38;5;196m'
green='\033[38;5;46m'
yellow='\033[38;5;226m'
blue='\033[38;5;27m'
purple='\033[38;5;129m'
cyan='\033[38;5;51m'
reset='\033[0m'

# دانلود برنامه warpendpoint (در مسیر فعلی)
download_warpendpoint() {
    if [[ ! -f "./warpendpoint" ]]; then
        echo -e "${cyan}در حال دانلود warpendpoint...${reset}"
        # در اینجا فرض شده معماری سیستم amd64 است؛ در صورت نیاز می‌توانید تغییر دهید
        curl -L -o warpendpoint -# --retry 2 "https://raw.githubusercontent.com/Ptechgithub/warp/main/endip/amd64"
        chmod +x warpendpoint
    fi
}

# تولید 100 آی‌پی یونیک بر اساس آی‌پی‌های پایه IPv4 وارپ
generate_ipv4() {
    local total=100
    local bases=("162.159.192" "162.159.193" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99")
    temp=()
    while [ "$(printf "%s\n" "${temp[@]}" | sort -u | wc -l)" -lt "$total" ]; do
        idx=$(( RANDOM % ${#bases[@]} ))
        ip="${bases[$idx]}.$(( RANDOM % 256 ))"
        if ! printf "%s\n" "${temp[@]}" | grep -qx "$ip"; then
            temp+=("$ip")
        fi
    done
}

# تولید 100 آی‌پی یونیک IPv6 بر اساس آی‌پی‌های پایه وارپ
generate_ipv6() {
    local total=100
    local bases=("2606:4700:d0::" "2606:4700:d1::")
    temp=()
    rand_hex() {
        printf '%x' $(( RANDOM % 65536 ))
    }
    while [ "$(printf "%s\n" "${temp[@]}" | sort -u | wc -l)" -lt "$total" ]; do
        idx=$(( RANDOM % ${#bases[@]} ))
        seg1=$(rand_hex)
        seg2=$(rand_hex)
        seg3=$(rand_hex)
        seg4=$(rand_hex)
        ip="[${bases[$idx]}${seg1}:${seg2}:${seg3}:${seg4}]"
        if ! printf "%s\n" "${temp[@]}" | grep -qx "$ip"; then
            temp+=("$ip")
        fi
    done
}

# اجرای اسکن و نمایش نتایج
scan_results() {
    # ذخیره آی‌پی‌های تولید شده در فایل ip.txt
    printf "%s\n" "${temp[@]}" | sort -u > ip.txt
    ulimit -n 102400
    chmod +x warpendpoint >/dev/null 2>&1
    if [[ -x "./warpendpoint" ]]; then
        ./warpendpoint
    else
        echo -e "${red}warpendpoint یافت نشد یا اجرا نشد.${reset}"
        exit 1
    fi

    clear
    if [[ -f result.csv ]]; then
        echo -e "${purple}نتایج اسکن:${reset}"
        awk -F, '$3!="timeout ms" {print "Endpoint: "$1" | Packet Loss: "$2" | Delay: "$3}' result.csv | sort -t, -nk2 -nk3 | uniq | head -n 11
        best_ipv4=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+" result.csv | head -n 1)
        best_ipv6=$(grep -oE "\[.*\]:[0-9]+" result.csv | head -n 1)
        delay=$(grep -oE "[0-9]+ ms|timeout" result.csv | head -n 1)
        echo ""
        echo -e "${green}نتایج در فایل result.csv ذخیره شد.${reset}"
        echo ""
        if [[ -n "$best_ipv4" ]]; then
            echo -e "${purple}************************************${reset}"
            echo -e "${purple}*         ${yellow}Best IPv4:Port${purple}         *${reset}"
            echo -e "${purple}*                                  *${reset}"
            echo -e "${purple}*         ${cyan}$best_ipv4${purple}         *${reset}"
            echo -e "${purple}*         ${cyan}Delay: ${green}[$delay]${purple}        *${reset}"
            echo -e "${purple}************************************${reset}"
        elif [[ -n "$best_ipv6" ]]; then
            echo -e "${purple}********************************************${reset}"
            echo -e "${purple}*        ${yellow}Best [IPv6]:Port${purple}             *${reset}"
            echo -e "${purple}*                                          *${reset}"
            echo -e "${purple}* ${cyan}$best_ipv6${purple} *${reset}"
            echo -e "${purple}*         ${cyan}Delay: ${green}[$delay]${purple}              *${reset}"
            echo -e "${purple}********************************************${reset}"
        else
            echo -e "${red}هیچ آی‌پی معتبری یافت نشد.${reset}"
        fi
        rm -f warpendpoint ip.txt
    else
        echo -e "${red}فایل result.csv یافت نشد؛ اسکن به درستی انجام نشد.${reset}"
    fi
}

# اجرای اصلی
clear
echo -e "${cyan}اسکنر آی‌پی وارپ تمیز${reset}"
echo -e "${blue}انتخاب نسل آی‌پی برای اسکن:${reset}"
echo -e "${yellow}[1] IPv4${reset}"
echo -e "${yellow}[2] IPv6${reset}"
echo -ne "${green}انتخاب شما: ${reset}"
read -r choice
case "$choice" in
    1)
        download_warpendpoint
        generate_ipv4
        scan_results
        ;;
    2)
        download_warpendpoint
        generate_ipv6
        scan_results
        ;;
    *)
        echo -e "${red}انتخاب نامعتبر.${reset}"
        exit 1
        ;;
esac
