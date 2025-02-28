#!/bin/bash
# Warp IP Scanner & WireGuard Config Generator
# بهینه‌سازی شده برای سازگاری با پلتفرم‌های مختلف

VERSION="1.1"

# ----- تنظیم متغیرها و ثابت‌ها -----

# رنگ‌ها (با قابلیت غیرفعال‌سازی در ترمینال‌های بدون پشتیبانی رنگ)
if [ -t 1 ]; then  # بررسی پشتیبانی ترمینال از رنگ
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

# تنظیم مسیر فایل‌های موقت و خروجی بر اساس پلتفرم
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    DEFAULT_CONFIG_PATH="$HOME/wg-config.conf"
    TEMP_DIR="/tmp/warp-scanner"
elif [[ "$OSTYPE" == "linux-android"* || -d "/storage/emulated/0" ]]; then
    # Android (Termux یا مشابه)
    DEFAULT_CONFIG_PATH="/storage/emulated/0/wg-config.conf"
    TEMP_DIR="$HOME/warp-scanner-tmp"
else
    # Linux و سایر سیستم‌ها
    DEFAULT_CONFIG_PATH="$HOME/wg-config.conf"
    TEMP_DIR="/tmp/warp-scanner"
fi

# ایجاد دایرکتوری موقت
mkdir -p "$TEMP_DIR"
IP_FILE="$TEMP_DIR/ip.txt"
RESULT_FILE="$TEMP_DIR/result.txt"
CSV_FILE="$TEMP_DIR/result.csv"
BEST_IPS_FILE="$TEMP_DIR/best_ips.txt"

# مشخص کردن معماری سیستم برای دانلود فایل warpendpoint مناسب
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
        ENDPOINT_ARCH="amd64"  # پیش‌فرض
        ;;
esac

# ----- توابع و عملکردها -----

# نمایش پیام خطا و خروج
error_exit() {
    echo -e "${red}خطا: $1${reset}" >&2
    exit 1
}

# نمایش اطلاعات پیشرفت
show_progress() {
    echo -e "${blue}$1${reset}"
}

# پاک‌سازی فایل‌های موقت
cleanup() {
    show_progress "در حال پاک‌سازی فایل‌های موقت..."
    rm -rf "$TEMP_DIR"
    echo -e "${green}پاک‌سازی انجام شد.${reset}"
}
trap cleanup EXIT INT TERM

# بررسی به‌روزرسانی‌ها
check_update() {
    show_progress "در حال بررسی به‌روزرسانی‌ها..."
    
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        echo -e "${yellow}curl یا wget یافت نشد. بررسی به‌روزرسانی رد شد.${reset}"
        return
    fi
    
    local latest_version
    if command -v curl &>/dev/null; then
        latest_version=$(curl -s -m 5 "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/version.txt" 2>/dev/null || echo "$VERSION")
    else
        latest_version=$(wget -q -O - -T 5 "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/version.txt" 2>/dev/null || echo "$VERSION")
    fi
    
    if [[ "$latest_version" != "$VERSION" && "$latest_version" != "" ]]; then
        echo -e "${yellow}نسخه جدید ($latest_version) موجود است. برای به‌روزرسانی به https://github.com/void1x0/WARP-Scanner مراجعه کنید.${reset}"
    else
        echo -e "${green}شما در حال استفاده از آخرین نسخه ($VERSION) هستید.${reset}"
    fi
}

# دانلود فایل با پشتیبانی از curl و wget
download_file() {
    local url="$1"
    local output="$2"
    local msg="$3"
    
    echo -e "${cyan}در حال دانلود $msg...${reset}"
    
    if command -v curl &>/dev/null; then
        if ! curl -L -o "$output" --retry 3 --retry-delay 2 -m 60 -# "$url"; then
            error_exit "دانلود ناموفق بود. لطفاً اتصال اینترنت خود را بررسی کنید."
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --show-progress -O "$output" --tries=3 --timeout=60 "$url"; then
            error_exit "دانلود ناموفق بود. لطفاً اتصال اینترنت خود را بررسی کنید."
        fi
    else
        error_exit "curl یا wget یافت نشد. لطفاً یکی از آن‌ها را نصب کنید."
    fi
}

# دانلود warpendpoint اگر در دایرکتوری فعلی موجود نباشد
download_warpendpoint() {
    local endpoint_path="$TEMP_DIR/warpendpoint"
    
    if [[ ! -f "$endpoint_path" ]]; then
        download_file "https://raw.githubusercontent.com/void1x0/WARP-Scanner/main/endip/$ENDPOINT_ARCH" "$endpoint_path" "warpendpoint"
        chmod +x "$endpoint_path"
        
        # بررسی موفقیت‌آمیز بودن دانلود
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "فایل warpendpoint قابل اجرا نیست یا خراب است."
        fi
    fi
}

# تولید 100 آدرس IPv4 منحصر به فرد از پایه‌های گسترده Warp
generate_ipv4() {
    show_progress "در حال تولید آدرس‌های IPv4..."
    local total=100
    # لیست گسترده‌ای از پایه‌های IPv4 از Warp
    local bases=("162.159.192" "162.159.193" "162.159.194" "162.159.195" "188.114.96" "188.114.97" "188.114.98" "188.114.99" "188.114.100" "188.114.101")
    
    # روش بهینه‌تر برای تولید آی‌پی‌های منحصر به فرد با استفاده از temp_array
    local temp_array=()
    while [ "${#temp_array[@]}" -lt "$total" ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local ip="${bases[$idx]}.$(( RANDOM % 256 ))"
        
        # بررسی تکراری نبودن IP
        local is_duplicate=0
        for existing_ip in "${temp_array[@]}"; do
            if [[ "$existing_ip" == "$ip" ]]; then
                is_duplicate=1
                break
            fi
        done
        
        if [[ "$is_duplicate" -eq 0 ]]; then
            temp_array+=("$ip")
        fi
    done
    
    # ذخیره لیست در فایل
    printf "%s\n" "${temp_array[@]}" > "$IP_FILE"
    echo -e "${green}$total آدرس IPv4 تولید شد.${reset}"
}

# تولید 100 آدرس IPv6 منحصر به فرد از پایه‌های گسترده Warp
generate_ipv6() {
    show_progress "در حال تولید آدرس‌های IPv6..."
    local total=100
    # لیست گسترده‌ای از پایه‌های IPv6
    local bases=("2606:4700:d0::" "2606:4700:d1::" "2606:4700:110::")
    
    # تابع کمکی برای تولید مقدار هگزادسیمال تصادفی
    rand_hex() {
        printf '%x' $(( RANDOM % 65536 ))
    }
    
    # روش بهینه‌تر برای تولید آی‌پی‌های منحصر به فرد با استفاده از temp_array
    local temp_array=()
    while [ "${#temp_array[@]}" -lt "$total" ]; do
        local idx=$(( RANDOM % ${#bases[@]} ))
        local seg1=$(rand_hex)
        local seg2=$(rand_hex)
        local seg3=$(rand_hex)
        local seg4=$(rand_hex)
        local ip="[${bases[$idx]}${seg1}:${seg2}:${seg3}:${seg4}]"
        
        # بررسی تکراری نبودن IP
        local is_duplicate=0
        for existing_ip in "${temp_array[@]}"; do
            if [[ "$existing_ip" == "$ip" ]]; then
                is_duplicate=1
                break
            fi
        done
        
        if [[ "$is_duplicate" -eq 0 ]]; then
            temp_array+=("$ip")
        fi
    done
    
    # ذخیره لیست در فایل
    printf "%s\n" "${temp_array[@]}" > "$IP_FILE"
    echo -e "${green}$total آدرس IPv6 تولید شد.${reset}"
}

# تبدیل CSV به TXT
convert_csv_to_txt() {
    if [[ -f "$CSV_FILE" ]]; then
        if command -v awk &>/dev/null; then
            awk -F, '$3!="timeout ms" {print "Endpoint: "$1" | Delay: "$3}' "$CSV_FILE" | sort -t, -nk3 | uniq > "$RESULT_FILE"
        else
            # جایگزین ساده‌تر برای سیستم‌هایی که awk ندارند
            while IFS=',' read -r endpoint _ delay_ms _; do
                if [[ "$delay_ms" != "timeout ms" ]]; then
                    echo "Endpoint: $endpoint | Delay: $delay_ms"
                fi
            done < "$CSV_FILE" | sort | uniq > "$RESULT_FILE"
        fi
        rm -f "$CSV_FILE"
    fi
}

# اسکن موازی IP‌ها برای بهبود سرعت
parallel_scan() {
    local ip_type="$1"
    local endpoint_path="$TEMP_DIR/warpendpoint"
    local batch_size=10
    local total_ips=$(wc -l < "$IP_FILE")
    local batches=$((total_ips / batch_size))
    
    show_progress "در حال اسکن آدرس‌های IP به صورت موازی..."
    
    # تنظیم ulimit برای پلتفرم‌های مختلف
    if [[ "$OSTYPE" != "darwin"* ]]; then  # macOS محدودیت‌های خاصی دارد
        ulimit -n 102400 2>/dev/null || ulimit -n 4096 2>/dev/null || true
    fi
    
    # اطمینان از قابل اجرا بودن warpendpoint
    if [[ ! -x "$endpoint_path" ]]; then
        chmod +x "$endpoint_path" 2>/dev/null
        if [[ ! -x "$endpoint_path" ]]; then
            error_exit "warpendpoint قابل اجرا نیست."
        fi
    fi
    
    # تقسیم فایل IP به چند بخش کوچک‌تر برای اسکن موازی
    for ((i=0; i<batches; i++)); do
        local start=$((i * batch_size + 1))
        local end=$((start + batch_size - 1))
        
        # ایجاد فایل‌های موقت برای هر دسته
        local batch_file="$TEMP_DIR/batch_$i.txt"
        sed -n "${start},${end}p" "$IP_FILE" > "$batch_file"
        
        # اجرای warpendpoint برای هر دسته در پس‌زمینه
        (
            "$endpoint_path" -f "$batch_file" -o "$TEMP_DIR/result_$i.csv" >/dev/null 2>&1
        ) &
        
        # نمایش پیشرفت
        echo -ne "\r${cyan}پیشرفت: $((i * 100 / batches))%${reset}"
    done
    
    # انتظار برای تکمیل تمام فرآیندهای پس‌زمینه
    wait
    echo -e "\r${green}پیشرفت: 100%${reset}"
    
    # ترکیب نتایج
    if ls "$TEMP_DIR"/result_*.csv 1>/dev/null 2>&1; then
        cat "$TEMP_DIR"/result_*.csv > "$CSV_FILE"
        rm -f "$TEMP_DIR"/result_*.csv "$TEMP_DIR"/batch_*.txt
        convert_csv_to_txt
    else
        error_exit "هیچ نتیجه‌ای از اسکن به دست نیامد."
    fi
}

# اجرای اسکن و نمایش نتایج
scan_results() {
    local ip_type="$1"
    
    if [[ "$ip_type" == "ipv4" ]]; then
        generate_ipv4
    elif [[ "$ip_type" == "ipv6" ]]; then
        generate_ipv6
    else
        error_exit "نوع IP نامعتبر است."
    fi
    
    download_warpendpoint
    parallel_scan "$ip_type"
    
    clear
    if [[ -f "$RESULT_FILE" ]]; then
        echo -e "${magenta}نتایج اسکن:${reset}"
        head -n 11 "$RESULT_FILE"
        
        # استخراج بهترین آدرس‌ها
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
        echo -e "${green}نتایج در $RESULT_FILE ذخیره شده‌اند${reset}"
        echo ""
        
        if [[ "$ip_type" == "ipv4" && -n "$best_ipv4" ]]; then
            echo -e "${magenta}******** بهترین IPv4 ********${reset}"
            echo -e "${blue}$best_ipv4${reset}"
            echo -e "${blue}تأخیر: ${green}[$delay]${reset}"
            # ذخیره بهترین IP برای استفاده در تنظیمات WireGuard
            echo "$best_ipv4" > "$BEST_IPS_FILE"
        elif [[ "$ip_type" == "ipv6" && -n "$best_ipv6" ]]; then
            echo -e "${magenta}******** بهترین IPv6 ********${reset}"
            echo -e "${blue}$best_ipv6${reset}"
            echo -e "${blue}تأخیر: ${green}[$delay]${reset}"
            # ذخیره بهترین IP برای استفاده در تنظیمات WireGuard
            echo "$best_ipv6" > "$BEST_IPS_FILE"
        else
            echo -e "${red}هیچ IP معتبری یافت نشد.${reset}"
        fi
    else
        echo -e "${red}$RESULT_FILE یافت نشد. ممکن است اسکن با شکست مواجه شده باشد.${reset}"
    fi
    
    # پرسش برای بازگشت به منوی اصلی
    echo ""
    echo -ne "${cyan}آیا می‌خواهید به منوی اصلی بازگردید؟ (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
        main_menu
    fi
}

# تولید یک فایل پیکربندی WireGuard با کلیدهای جدید
generate_wg_config() {
    echo -ne "${cyan}آیا می‌خواهید پیکربندی WireGuard را تولید کنید؟ (y/n): ${reset}"
    read -r resp
    if [[ "$resp" =~ ^[Yy]$ ]]; then
        local endpoint=""
        
        echo -ne "${cyan}آیا می‌خواهید اسکن IP را برای یافتن بهترین نقطه اتصال انجام دهید؟ (y/n): ${reset}"
        read -r scan_choice
        if [[ "$scan_choice" =~ ^[Yy]$ ]]; then
            echo -e "${cyan}نوع IP را برای اسکن انتخاب کنید: ${reset}"
            echo -e "${yellow}[1] IPv4${reset}"
            echo -e "${yellow}[2] IPv6${reset}"
            echo -ne "${cyan}انتخاب شما: ${reset}"
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
                    echo -e "${yellow}انتخاب نامعتبر. از نقطه اتصال پیش‌فرض استفاده می‌شود.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        else
            echo -e "${cyan}گزینه نقطه اتصال را انتخاب کنید:${reset}"
            echo -e "${yellow}[1] پیش‌فرض (engage.cloudflareclient.com:2408)${reset}"
            echo -e "${yellow}[2] Warp جدید (engage.cloudflareclient.com:2409)${reset}"
            echo -ne "${cyan}انتخاب شما: ${reset}"
            read -r ep_choice
            
            case "$ep_choice" in
                1)
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
                2)
                    endpoint="engage.cloudflareclient.com:2409"
                    ;;
                *)
                    echo -e "${yellow}انتخاب نامعتبر. از نقطه اتصال پیش‌فرض استفاده می‌شود.${reset}"
                    endpoint="engage.cloudflareclient.com:2408"
                    ;;
            esac
        fi
        
        # تولید کلیدهای جدید WireGuard
        local private_key=""
        local public_key=""
        
        if command -v wg &>/dev/null; then
            private_key=$(wg genkey)
            public_key=$(echo "$private_key" | wg pubkey)
        else
            echo -e "${red}wireguard-tools نصب نشده است. لطفاً wg را نصب کنید.${reset}"
            echo -e "${yellow}بازگشت به منوی اصلی...${reset}"
            sleep 2
            main_menu
            return
        fi
        
        # آدرس‌های پیش‌فرض کلاینت WireGuard طبق پیکربندی نمونه
        local wg_ipv4="172.16.0.2/32"
        local wg_ipv6="2606:4700:110:848e:fec7:926a:f8d:1ca/128"
        
        # مسیر فایل پیکربندی
        echo -ne "${cyan}مسیر فایل پیکربندی را وارد کنید (پیش‌فرض: $DEFAULT_CONFIG_PATH): ${reset}"
        read -r config_path
        if [[ -z "$config_path" ]]; then
            config_path="$DEFAULT_CONFIG_PATH"
        fi
        
        # اطمینان از وجود دایرکتوری والد
        mkdir -p "$(dirname "$config_path")" 2>/dev/null
        
        # نوشتن فایل پیکربندی
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
        
        # بررسی موفقیت‌آمیز بودن نوشتن فایل
        if [[ $? -eq 0 ]]; then
            echo -e "${green}پیکربندی WireGuard تولید و در $config_path ذخیره شد${reset}"
            # محدود کردن دسترسی‌های فایل پیکربندی
            chmod 600 "$config_path" 2>/dev/null || true
            
            echo -e "${magenta}جزئیات پیکربندی:${reset}"
            echo -e "${cyan}کلید خصوصی: ${green}$private_key${reset}"
            echo -e "${cyan}کلید عمومی: ${green}$public_key${reset}"
            echo -e "${cyan}آدرس IPv4: ${green}$wg_ipv4${reset}"
            echo -e "${cyan}آدرس IPv6: ${green}$wg_ipv6${reset}"
            echo -e "${cyan}نقطه اتصال: ${green}$endpoint${reset}"
            echo -e "${cyan}DNS: ${green}1.1.1.1, 1.0.0.1${reset}"
            echo -e "${cyan}MTU: ${green}1280${reset}"
        else
            echo -e "${red}خطا در نوشتن فایل پیکربندی. لطفاً دسترسی‌ها را بررسی کنید.${reset}"
        fi
    else
        echo -e "${yellow}تولید پیکربندی WireGuard رد شد.${reset}"
    fi
    
    # پرسش برای بازگشت به منوی اصلی
    echo ""
    echo -ne "${cyan}آیا می‌خواهید به منوی اصلی بازگردید؟ (y/n): ${reset}"
    read -r return_to_menu
    if [[ "$return_to_menu" =~ ^[Yy]$ ]]; then
        main_menu
    fi
}

# منوی اصلی
main_menu() {
    clear
    echo -e "${magenta}Warp IP Scanner & WireGuard Config Generator v$VERSION${reset}"
    check_update
    echo -e "${blue}یک گزینه را انتخاب کنید:${reset}"
    echo -e "${yellow}[1] اسکن IPv4${reset}"
    echo -e "${yellow}[2] اسکن IPv6${reset}"
    echo -e "${yellow}[3] تولید پیکربندی WireGuard${reset}"
    echo -e "${yellow}[0] خروج${reset}"
    echo -ne "${cyan}انتخاب شما: ${reset}"
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
        0)
            echo -e "${green}در حال خروج...${reset}"
            exit 0
            ;;
        *)
            echo -e "${red}انتخاب نامعتبر.${reset}"
            sleep 2
            main_menu
            ;;
    esac
}

# ----- شروع برنامه -----

# بررسی وجود ابزارهای اساسی مورد نیاز
for cmd in grep sort; do
    if ! command -v "$cmd" &>/dev/null; then
        error_exit "دستور $cmd یافت نشد. لطفاً بسته‌های پایه‌ای سیستم را نصب کنید."
    fi
done

# شروع برنامه با نمایش منوی اصلی
main_menu
