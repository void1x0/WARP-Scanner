#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# نسخه: V = 71
# پیش‌نیاز: Python 3 و بسته‌های requests, rich, retrying, icmplib, alive_progress, cryptography
# همچنین در Termux باید wget, curl و termux-setup-storage موجود باشد.

import urllib.request
import urllib.parse
from urllib.parse import quote
import os
import sys
import re
import socket
import time
import random
import subprocess
import json
import base64
import datetime

# نصب بسته‌های مورد نیاز
try:
    import requests
except Exception:
    print("Requests module not installed. Installing now...")
    os.system('pip install requests')
    import requests

try:
    import rich
except Exception:
    print("Rich module not installed. Installing now...")
    os.system('pip install rich')
    import rich
from rich.console import Console
from rich.prompt import Prompt
from rich import print as rprint
from rich.table import Table

try:
    import retrying
except Exception:
    print("retrying module not installed. Installing now...")
    os.system('pip install retrying')
    import retrying
from retrying import retry
from requests.exceptions import ConnectionError

try:
    from icmplib import ping as pinging
except Exception:
    os.system('pip install icmplib')
    from icmplib import ping as pinging

try:
    from alive_progress import alive_bar
except Exception:
    os.system("pip install alive_progress")
    from alive_progress import alive_bar

# در صورت نیاز cryptography نصب می‌شود
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey 
    from cryptography.hazmat.primitives import serialization
except Exception:
    print("cryptography module not installed. Installing now...")
    os.system('pkg install python3 rust binutils-is-llvm -y')
    os.system('python3 -m pip install cryptography')
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey 
    from cryptography.hazmat.primitives import serialization

# متغیرهای گلوبال
api = ''
ports = [1074, 894, 908, 878]
console = Console()
wire_config_temp = ''
wire_c = 1
wire_p = 0
send_msg_wait = 0
results = []
resultss = []
save_result = []
save_best = []
best_result = []
WoW_v2 = ''
isIran = ''
max_workers_number = 0
do_you_save = '2'
which = ''
ping_range = 'n'
need_port = ''       # برای ذخیره پورت در خروجی
polrn_block = ''     # برای مسدودسازی سایت‌های پورن
# متغیر "what" از منوی اصلی تعیین خواهد شد

#############################
# توابع کمکی و نصب ماژول‌ها
#############################

def gt_resolution():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def urlencode(string):
    if string is None:
        return None
    return urllib.parse.quote(string, safe='a-zA-Z0-9.~_-')

def info():
    console.clear()
    
    table = Table(show_header=True, title="Info", header_style="bold blue")
    table.add_column("Creator", width=15)
    table.add_column("contact", justify="right")
    table.add_row("arshiacomplus", "1 - Telegram")
    table.add_row("arshiacomplus", "2 - GitHub")
    console.print(table)
    
    print('\nEnter a Number\n')
    options2 = {"1": "open Telegram Channel", "2": "open GitHub", "0": "Exit"}
    for key, value in options2.items():
        rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    whats2 = Prompt.ask("Choose an option", choices=list(options2.keys()), default="1")
    
    if whats2 == '0':
        os.execv(sys.executable, ['python'] + sys.argv)
    elif whats2 == '1':
        os.system("termux-open-url 'https://t.me/arshia_mod_fun'")
    elif whats2 == '2':
        os.system("termux-open-url 'https://github.com/arshiacomplus/'")

def input_p(pt, options):
    os.system('clear')
    options.update({"0": "Exit"})
    print(pt)
    for key, value in options.items():
        rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    whats = Prompt.ask("Choose an option", choices=list(options.keys()), default="1")
    if whats == '0':
        os.execv(sys.executable, ['python'] + sys.argv)
    return whats

def byte_to_base64(myb):
    return base64.b64encode(myb).decode('utf-8')
     
def generate_public_key(key_bytes):
    private_key = X25519PrivateKey.from_private_bytes(key_bytes)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )    
    return public_key_bytes

def generate_private_key():
    key = os.urandom(32)    
    key = list(key)
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64    
    return bytes(key)

#############################
# تابع ایجاد حساب کلودفلر (یکپارچه‌سازی نسخه قبلی free_cloudflare_account2)
#############################
def free_cloudflare_account():
    @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
    def file_o():
        try:
            response = urllib.request.urlopen("https://fscarmen.cloudflare.now.cc/wg", timeout=30).read().decode('utf-8')
            return response
        except Exception:
            response = requests.get("https://fscarmen.cloudflare.now.cc/wg", timeout=30)
            return response.text
    response = file_o()
    PublicKey = response[response.index(':')+2:response.index('\n')]
    PrivateKey = response[response.index('\n')+13:]
    reserved = [222, 6, 184]
    return ["2606:4700:110:8d48:52cb:c565:3a80:c416/128", PrivateKey, reserved, PublicKey]

def register_key_on_CF(pub_key):
    url = 'https://api.cloudflareclient.com/v0a4005/reg'
    body = {"key": pub_key,
            "install_id": "",
            "fcm_token": "",
            "warp_enabled": True,
            "tos": datetime.datetime.now().isoformat()[:-3] + "+07:00",
            "type": "Android",
            "model": "PC",
            "locale": "en_US"}
    bodyString = json.dumps(body)
    headers = {'Content-Type': 'application/json; charset=UTF-8',
               'Host': 'api.cloudflareclient.com',
               'Connection': 'Keep-Alive',
               'Accept-Encoding': 'gzip',
               'User-Agent': 'okhttp/3.12.1',
               "CF-Client-Version": "a-6.30-3596"}
    r = requests.post(url, data=bodyString, headers=headers)
    return r

def bind_keys():
    priv_bytes = generate_private_key()
    priv_string = byte_to_base64(priv_bytes)
    pub_bytes = generate_public_key(priv_bytes)
    pub_string = byte_to_base64(pub_bytes)
    result = register_key_on_CF(pub_string)
    if result.status_code == 200:
        try:
            z = json.loads(result.content)
            client_id = z['config']["client_id"]      
            cid_byte = base64.b64decode(client_id)
            reserved = [int(j) for j in cid_byte]
            return '2606:4700:110:846c:e510:bfa1:ea9f:5247/128', priv_string, reserved, 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='
        except Exception as e:
            print('Something went wrong with api')
            exit()
            
def fetch_config_from_api():
    global api, what
    if api == '':
        which_api = input_p('Which Api \n', {'1': 'First api', '2': 'Second api (need VPN just for install lib)'})
        api = which_api
    else:
        which_api = api
    if which_api == '2':
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey 
            from cryptography.hazmat.primitives import serialization
        except Exception:
            try:
                print("cryptography module not installed. Installing now...")
                os.system('pkg install python3 rust binutils-is-llvm -y')
                os.system('python3 -m pip install cryptography')
            except Exception:
                os.system("wget https://github.com/pyca/cryptography/archive/refs/tags/43.0.0.tar.gz")
                os.system("tar -zxvf 43.0.0.tar.gz")
                os.chdir("cryptography-43.0.0")
                os.system("pip install .")
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        except Exception:
            print('Something went wrong with cryptography')
            exit()
        keys = bind_keys()
        keys = list(keys)
        return {
            'PrivateKey': keys[1],
            'PublicKey':  keys[3],
            'Reserved':  keys[2],
            'Address':  keys[0]
        }
        
    @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
    def file_o():
        try:
            response = urllib.request.urlopen("http://s9.serv00.com:1074/arshiacomplus/api/wirekey", timeout=30).read().decode('utf-8')
            return response
        except Exception:
            response = requests.get("http://s9.serv00.com:1074/arshiacomplus/api/wirekey", timeout=30)
            return response.text
    b = file_o()
    b = b.split("\n")
    Address_key = b[0][b[0].index(":")+2:]
    private_key = b[1][b[1].index(":")+2:]
    reserved = b[2][b[2].index(":")+2:].split(" ")
    if len(reserved) > 3:
        reserved.pop(3)
    reserved = [int(item) for item in reserved]
    pub_key = b[3][b[3].index(":")+2:]
    return {
        'PrivateKey': private_key,
        'PublicKey': pub_key,
        'Reserved': reserved,
        'Address': Address_key
    }

def upload_to_bashupload(config_data):
    @retry(stop_max_attempt_number=3, wait_fixed=2000, retry_on_exception=lambda x: isinstance(x, ConnectionError))
    def file_o():
        files = {'file': ('output.json', config_data)}
        try:
            response = requests.post('https://bashupload.com/', files=files, timeout=30)
        except Exception:
            response = requests.post('https://bashupload.com/', files=files, timeout=50)
        return response
    try:
        response = file_o()
        if response.ok:
            download_link = response.text.strip()
            download_link_with_query = download_link[59:len(download_link)-27] + "?download=1"
            console.print(f'[green]Your link: {download_link_with_query}[/green]')
        else:
            console.print("[red]Something happened with creating the link[/red]", style="bold red")
    except Exception as e:
        console.print(f"[red]An error occurred: {e}[/red]", style="bold red")
        
def create_ip_range(start_ip, end_ip):
    start = list(map(int, start_ip.split('.')))
    end = list(map(int, end_ip.split('.')))
    temp = start[:]
    ip_range = []
    while temp != end:
        ip_range.append('.'.join(map(str, temp)))
        temp[3] += 1
        for i2 in (3, 2, 1):
            if temp[i2] == 256:
                temp[i2] = 0
                temp[i2-1] += 1
    ip_range.append(end_ip)
    return ip_range

def scan_ip_port(ip, results: list):
    port = ports[random.randint(0, 3)]
    icmp = pinging(ip, count=4, interval=1, timeout=5, privileged=False)
    if icmp.is_alive:
        results.append((ip, port, float(icmp.avg_rtt), icmp.packet_loss, icmp.jitter))

def check_ipv6():
    try:
        ipv6 = requests.get('http://v6.ipv6-test.com/api/myip.php', timeout=15)
        if ipv6.status_code == 200:
            ipv6 = "[green]Available[/green]"
    except Exception:
        ipv6 = "Unavailable"
    try:
        ipv4 = requests.get('http://v4.ipv6-test.com/api/myip.php', timeout=15)
        if ipv4.status_code == 200:
            ipv4 = "[green]Available[/green]"
    except Exception:
        ipv4 = "Unavailable"
    return [ipv4, ipv6]

#############################
# توابع اسکن آی‌پی
#############################
def main_v6():
    global which, do_you_save
    resultss = []
    def generate_ipv6():
        return f"2606:4700:d{random.randint(0, 1)}::{random.randint(0, 65535):x}:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}"
    def ping_ip(ip, port):
        icmp = pinging(ip, count=4, interval=1, timeout=5, privileged=False, family='ipv6')
        if icmp.is_alive:
            resultss.append((ip, port, float(icmp.avg_rtt), icmp.packet_loss, icmp.jitter))
    console = Console()
    ports_to_check = [1074, 864]
    random_ip = generate_ipv6()
    best_ping = 1000
    best_ip = ""
    table = Table(show_header=True, title="IP Scan Results", header_style="bold blue")
    table.add_column("IP", style="dim", width=15)
    table.add_column("Port", justify="right")
    table.add_column("Ping (ms)", justify="right")
    table.add_column("Packet Loss (%)", justify="right")
    table.add_column("Jitter (ms)", justify="right")
    table.add_column("Score", justify="right")
    executor =  None
    try:
        futures = []
        from concurrent.futures import ThreadPoolExecutor
        executor = ThreadPoolExecutor(max_workers=800)
        for _ in range(101):
            futures.append(executor.submit(ping_ip, generate_ipv6(), ports_to_check[random.randint(0, 1)]))
        none = gt_resolution()
        bar_size = min(none-40, 20)
        if bar_size < 3:
            bar_size = 3
        elif bar_size > 1000:
            bar_size = 1000
        with alive_bar(total=len(futures), length=bar_size) as bar:
            for future in futures:
                time.sleep(0.01)
                future.result()
                bar()
    except Exception as E:
        rprint('[bold red]An Error: [/bold red]', E)
    finally:
        if executor:
            executor.shutdown(wait=True)
    extended_results = []
    for result in resultss:
        ip, port, ping, loss_rate, jitter = result
        if ping == 0.0:
            ping = 1000
        if float(jitter) == 0.0:
            jitter = 1000
        if loss_rate == 1.0:
            loss_rate = 1000
        loss_rate = loss_rate * 100
        combined_score = 0.5 * ping + 0.3 * loss_rate + 0.2 * jitter
        extended_results.append((ip, port, ping, loss_rate, jitter, combined_score))
    sorted_results = sorted(extended_results, key=lambda x: x[5])
    for ip, port, ping, loss_rate, jitter, combined_score in sorted_results:
        if which != '3' and do_you_save == '1':
            if loss_rate == 0.0 and ping != 0.0:
                if which in ["1", "2"]:
                    if need_port == "1":
                        if which == '2':
                            save_best.append("\n")
                            save_best.append(f'[{ip}]:{port}')
                        elif which == '1':
                            save_best.append(f'[{ip}]:{port},')
                    else:
                        if which == '2':
                            save_best.append("\n")
                            save_best.append(f'[{ip}]')
                        elif which == '1':
                            save_best.append(f'[{ip}],')
        if which == '3' and do_you_save == '1':
            if need_port == "2":
                save_best.append(f'[{ip}] | ping: {ping} packet_lose: {loss_rate} jitter: {jitter}\n')
            else:
                save_best.append(f'[{ip}]{port} | ping: {ping} packet_lose: {loss_rate} jitter: {jitter}\n')
        table.add_row(ip, str(port) if port else "878", f"{ping:.2f}" if ping else "None", f"{loss_rate:.2f}%", f"{jitter}", f"{combined_score:.2f}")
        if ping < best_ping:
            best_ping = ping
            best_ip = ip
    os.system("clear")
    console.print(table)
    port_random = ports_to_check[random.randint(0, len(ports_to_check) - 1)]
    if do_you_save == '1':
        if which != '2' and save_best:
            save_best[-1] = save_best[-1].rstrip(',')
        with open('/storage/emulated/0/result.csv', "w") as f:
            for j in save_best:
                f.write(j)
        print(' saved in /storage/emulated/0/result.csv !')
    best_ip_mix = ["" , 0]
    if best_ip:
        console.print(f"\n[bold green]Best IP : [{best_ip}]:{port_random} with ping time: {best_ping} ms[/bold green]")
        best_ip_mix[0] = f"[{best_ip}]"
        best_ip_mix[1] = port_random
    else:
        console.print(f"\n[bold green]Best IP : [{random_ip}]:{port_random} with ping time: {best_ping} ms[/bold green]")
        best_ip_mix[0] = f"[{random_ip}]"
        best_ip_mix[1] = port_random
    return best_ip_mix

def main():
    global which, max_workers_number, ping_range, results, save_result, what
    global do_you_save
    ping_range = ''
    results = []
    if do_you_save == '1':
        ping_range = input('\nping range (zero to what) [default = n]: ')
        if ping_range in ['n', 'N']:
            ping_range = '300'
    if what != '0':
        which_v = input_p('Choose an IP version\n', {"1": 'ipv4', "2": 'ipv6'})
        if which_v == "2":
            console.clear()
            best = main_v6()
            return best
    Cpu_speed = input_p('Scan power', {"1": "Faster", "2": "Slower"})
    if Cpu_speed == "1":
        max_workers_number = 1000
    elif Cpu_speed == "2":
        max_workers_number = 500
    console.clear()
    console.print("Please wait, scanning IP ...\n\n", style="blue")
    start_ips = ["188.114.96.0", "162.159.192.0", "162.159.195.0"]
    end_ips = ["188.114.99.224", "162.159.193.224", "162.159.195.224"]
    ports_local = [1074, 894, 908, 878]
    for start_ip, end_ip in zip(start_ips, end_ips):
        ip_range = create_ip_range(start_ip, end_ip)
        from concurrent.futures import ThreadPoolExecutor
        executor = ThreadPoolExecutor(max_workers=max_workers_number)
        print("\033[1;35m")
        try:
            futures = [executor.submit(scan_ip_port, ip, results) for ip in ip_range]
            none = gt_resolution()
            bar_size = min(none-40, 20)
            if bar_size < 3:
                bar_size = 3
            elif bar_size > 1000:
                bar_size = 1000
            with alive_bar(total=len(futures), length=bar_size) as bar:
                for future in futures:
                    time.sleep(0.01)
                    future.result()
                    bar()
        except Exception as E:
            print("Error :", E)
        finally:
            executor.shutdown(wait=True)
        print("\033[0m")
    extended_results = []
    for result in results:
        ip, port, ping, loss_rate, jitter = result
        if ping == 0.0:
            ping = 1000
        if float(jitter) == 0.0:
            jitter = 1000
        if loss_rate == 1.0:
            loss_rate = 1000
        loss_rate = loss_rate * 100
        combined_score = 0.5 * ping + 0.3 * loss_rate + 0.2 * jitter
        extended_results.append((ip, port, ping, loss_rate, jitter, combined_score))
    sorted_results = sorted(extended_results, key=lambda x: x[5])
    for ip, port, ping, loss_rate, jitter, combined_score in sorted_results[:10]:
        table = Table(show_header=True, title="IP Scan Results", header_style="bold blue")
        table.add_column("IP", style="dim", width=15)
        table.add_column("Port", justify="right")
        table.add_column("Ping (ms)", justify="right")
        table.add_column("Packet Loss (%)", justify="right")
        table.add_column("Jitter (ms)", justify="right")
        table.add_column("Score", justify="right")
        table.add_row(ip, str(port) if port else "878", f"{ping:.2f}" if ping else "None", f"{loss_rate:.2f}%", f"{jitter}", f"{combined_score:.2f}")
    console.print(table)
    best_result_local = sorted_results[0] if sorted_results else None
    if best_result_local and best_result_local[0] != "No IP":
        ip, port, ping, loss_rate, jitter, combined_score = best_result_local
        try:
            console.print(f"The best IP: {ip}:{port if port else 'N/A'} , ping: {ping:.2f} ms, packet loss: {loss_rate:.2f}%, {jitter:.2f} ms , score: {combined_score:.2f}", style="green")
        except TypeError:
            console.print(f"The best IP: {ip}:{port if port else '878'} , ping: None, packet loss: {loss_rate:.2f}% , {jitter:.2f} ms , score: {combined_score:.2f}", style="green")
        best_result_local = [f"{ip}", port]
    else:
        console.print("Nothing was found", style="red")
    t = False
    if what == '1':
        if do_you_save == '1':
            if which == "1":
                with open('/storage/emulated/0/result.csv', "w") as f:
                    for j in save_result[1:]:
                        if j != "\n":
                            f.write(j)
                            t = False
                        else:
                            if t == False:
                                f.write(",")
                            t = True
            else:
                with open('/storage/emulated/0/result.csv', "w") as f:
                    for j in save_result:
                        f.write(j)
            print(' saved in /storage/emulated/0/result.csv !')
    return best_result_local

#############################
# توابع تولید پیکربندی WireGuard و URL
#############################
def generate_wireguard_url(config, endpoint):
    global api, what
    required_keys = ['PrivateKey', 'PublicKey', 'Address']
    if not all(key in config and config[key] is not None for key in required_keys):
        print("Incomplete configuration. Missing one of the required keys or value is None.")
        return None
    if what in ['5', '6', '11', '12']:
        listt = config.get('Reserved', [])
        lostt2 = ','.join(str(num) for num in listt)
        config['Reserved'] = urlencode(lostt2)
        wireguard_urll = (
            f"wireguard://{urlencode(config['PrivateKey'])}@{endpoint}"
            f"?address=172.16.0.2/32,{urlencode(config['Address'])}&"
            f"publickey={urlencode(config['PublicKey'])}"
        )
        if what in ['11', '12']:
            wireguard_urll = (
                f"wireguard://{urlencode(config['PrivateKey'])}@{endpoint}"
                f"?wnoise=quic&address=172.16.0.2/32,{urlencode(config['Address'])}&keepalive=5&wpayloadsize=1-8&"
                f"publickey={urlencode(config['PublicKey'])}&wnoisedelay=1-3&wnoisecount=15&mtu=1330"
            )
        if config.get('Reserved'):
            wireguard_urll += f"&reserved={config['Reserved']}"
    else:
        wireguard_urll = (
            f"wireguard://{urlencode(config['PrivateKey'])}@{endpoint}"
            f"?address=172.16.0.2/32,{urlencode(config['Address'])}&"
            f"publickey={urlencode(config['PublicKey'])}"
        )
        listt = config.get('Reserved', [])
        if listt:
            lostt2 = ','.join(str(num) for num in listt)
            wireguard_urll += f"&reserved={urlencode(lostt2)}"
    wireguard_urll += "#Tel= @arshiacomplus wire"
    return wireguard_urll

#############################
# توابع مربوط به پیکربندی‌های WoW و WireGuard
#############################
def main2():
    global WoW_v2, what, polrn_block, best_result
    def main2_2():
        global WoW_v2, best_result
        try:
            all_key3 = free_cloudflare_account()
        except Exception as E:
            print('Try again Error =', E)
            exit()
        try:
            all_key2 = free_cloudflare_account()
        except Exception as E:
            print('Try again Error =', E)
            exit()
        os.system('clear')
        print('Make Wireguard')
        time.sleep(10)
        WoW_v2 += f'''
{{
    "remarks": "Tel= arshiacomplus - WoW",
    "log": {{
        "loglevel": "warning"
    }},
    "dns": {{
        "hosts": {{
            "geosite:category-ads-all": "127.0.0.1",
            "geosite:category-ads-ir": "127.0.0.1"'''
        if polrn_block == '1': 
            WoW_v2 += ''',
            "geosite:category-porn": "127.0.0.1"'''
        WoW_v2 += f'''
        }},
        "servers": [
            "https://94.140.14.14/dns-query",
            {{
                "address": "8.8.8.8",
                "domains": [
                    "geosite:category-ir",
                    "domain:.ir"
                ],
                "expectIPs": [
                    "geoip:ir"
                ],
                "port": 53
            }}
        ],
        "tag": "dns"
    }},
    "inbounds": [
        {{
            "port": 10808,
            "protocol": "socks",
            "settings": {{
                "auth": "noauth",
                "udp": true,
                "userLevel": 8
            }},
            "sniffing": {{
                "destOverride": [
                    "http",
                    "tls"
                ],
                "enabled": true,
                "routeOnly": true
            }},
            "tag": "socks-in"
        }},
        {{
            "port": 10809,
            "protocol": "http",
            "settings": {{
                "auth": "noauth",
                "udp": true,
                "userLevel": 8
            }},
            "sniffing": {{
                "destOverride": [
                    "http",
                    "tls"
                ],
                "enabled": true,
                "routeOnly": true
            }},
            "tag": "http-in"
        }},
        {{
            "listen": "127.0.0.1",
            "port": 10853,
            "protocol": "dokodemo-door",
            "settings": {{
                "address": "1.1.1.1",
                "network": "tcp,udp",
                "port": 53
            }},
            "tag": "dns-in"
        }}
    ],
    "outbounds": [
        {{
            "protocol": "wireguard",
            "settings": {{
                "address": [
                    "172.16.0.2/32",
                    "{all_key3[0]}"
                ],
                "mtu": 1280,
                "peers": [
                    {{
                        "endpoint": "{best_result[0]}:{best_result[1]}",
                        "publicKey": "{all_key3[3]}"
                    }}
                ],
                "reserved": {all_key3[2]},
                "secretKey": "{all_key3[1]}"
            }}'''
        if what == '14':
            WoW_v2 += ''',
            "keepAlive": 10,
            "wnoise": "quic",
            "wnoisecount": "10-15",
            "wpayloadsize": "1-8",
            "wnoisedelay": "1-3"'''
        WoW_v2 += f'''
        }},
        {{
            "protocol": "wireguard",
            "settings": {{
                "address": [
                    "172.16.0.2/32",
                    "{all_key2[0]}"
                ],
                "mtu": 1280,
                "peers": [
                    {{
                        "endpoint": "{best_result[0]}:{best_result[1]}",
                        "publicKey": "{all_key2[3]}"
                    }}
                ],
                "reserved": {all_key2[2]},
                "secretKey": "{all_key2[1]}"
            }}'''
        if what == '14':
            WoW_v2 += ''',
            "keepAlive": 10,
            "wnoise": "quic",
            "wnoisecount": "10-15",
            "wpayloadsize": "1-8",
            "wnoisedelay": "1-3"'''
        WoW_v2 += f'''
        }},
        {{
            "protocol": "dns",
            "tag": "dns-out"
        }},
        {{
            "protocol": "freedom",
            "settings": {{}},
            "tag": "direct"
        }},
        {{
            "protocol": "blackhole",
            "settings": {{
                "response": {{
                    "type": "http"
                }}
            }},
            "tag": "block"
        }}
    ],
    "policy": {{
        "levels": {{
            "8": {{
                "connIdle": 300,
                "downlinkOnly": 1,
                "handshake": 4,
                "uplinkOnly": 1
            }}
        }},
        "system": {{
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }}
    }},
    "routing": {{
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {{
                "inboundTag": [
                    "dns-in"
                ],
                "outboundTag": "dns-out",
                "type": "field"
            }},
            {{
                "ip": [
                    "8.8.8.8"
                ],
                "outboundTag": "direct",
                "port": "53",
                "type": "field"
            }},
            {{
                "domain": [
                    "geosite:category-ir",
                    "domain:.ir"
                ],
                "outboundTag": "direct",
                "type": "field"
            }},
            {{
                "ip": [
                    "geoip:ir",
                    "geoip:private"
                ],
                "outboundTag": "direct",
                "type": "field"
            }},
            {{
                "domain": [
                    "geosite:category-ads-all",
                    "geosite:category-ads-ir"'''
        if polrn_block == '1': 
            WoW_v2 += ''',
                    "geosite:category-porn"'''
        WoW_v2 += f'''
                ],
                "outboundTag": "block",
                "type": "field"
            }},
            {{
                "outboundTag": "warp-out",
                "type": "field",
                "network": "tcp,udp"
            }}
        ]
    }},
    "stats": {{}}
}},
{{
    "remarks": "Tel= arshiacomplus - Warp",
    "log": {{
        "loglevel": "warning"
    }},
    "dns": {{
        "hosts": {{
            "geosite:category-ads-all": "127.0.0.1",
            "geosite:category-ads-ir": "127.0.0.1"'''
        if polrn_block == '1': 
            WoW_v2 += ''',
            "geosite:category-porn": "127.0.0.1"'''
        WoW_v2 += f'''
        }},
        "servers": [
            "https://94.140.14.14/dns-query",
            {{
                "address": "8.8.8.8",
                "domains": [
                    "geosite:category-ir",
                    "domain:.ir"
                ],
                "expectIPs": [
                    "geoip:ir"
                ],
                "port": 53
            }}
        ],
        "tag": "dns"
    }},
    "inbounds": [
        {{
            "port": 10808,
            "protocol": "socks",
            "settings": {{
                "auth": "noauth",
                "udp": true,
                "userLevel": 8
            }},
            "sniffing": {{
                "destOverride": [
                    "http",
                    "tls"
                ],
                "enabled": true,
                "routeOnly": true
            }},
            "tag": "socks-in"
        }},
        {{
            "port": 10809,
            "protocol": "http",
            "settings": {{
                "auth": "noauth",
                "udp": true,
                "userLevel": 8
            }},
            "sniffing": {{
                "destOverride": [
                    "http",
                    "tls"
                ],
                "enabled": true,
                "routeOnly": true
            }},
            "tag": "http-in"
        }},
        {{
            "listen": "127.0.0.1",
            "port": 10853,
            "protocol": "dokodemo-door",
            "settings": {{
                "address": "1.1.1.1",
                "network": "tcp,udp",
                "port": 53
            }},
            "tag": "dns-in"
        }}
    ],
    "outbounds": [
        {{
            "protocol": "wireguard",
            "settings": {{
                "address": [
                    "172.16.0.2/32",
                    "{all_key[0]}"
                ],
                "mtu": 1280,
                "peers": [
                    {{
                        "endpoint": "{best_result[0]}:{best_result[1]}",
                        "publicKey": "{all_key[3]}"
                    }}
                ],
                "reserved": {all_key[2]},
                "secretKey": "{all_key[1]}"
            }},
            "streamSettings": {{
                "network": "tcp",
                "security": "",
                "sockopt": {{
                    "dialerProxy": "warp-ir"
                }}
            }},
            "tag": "warp-out"
        }},
        {{
            "protocol": "wireguard",
            "settings": {{
                "address": [
                    "172.16.0.2/32",
                    "{all_key2[0]}"
                ],
                "mtu": 1280,
                "peers": [
                    {{
                        "endpoint": "{best_result[0]}:{best_result[1]}",
                        "publicKey": "{all_key[3]}"
                    }}
                ],
                "reserved": {all_key2[2]},
                "secretKey": "{all_key2[1]}"
            }}'''
        if what == '13':
            WoW_v2 += ''',
            "keepAlive": 10,
            "wnoise": "quic",
            "wnoisecount": "10-15",
            "wpayloadsize": "1-8",
            "wnoisedelay": "1-3"'''
        WoW_v2 += f'''
        }},
        {{
            "protocol": "dns",
            "tag": "dns-out"
        }},
        {{
            "protocol": "freedom",
            "settings": {{}},
            "tag": "direct"
        }},
        {{
            "protocol": "blackhole",
            "settings": {{
                "response": {{
                    "type": "http"
                }}
            }},
            "tag": "block"
        }}
    ],
    "policy": {{
        "levels": {{
            "8": {{
                "connIdle": 300,
                "downlinkOnly": 1,
                "handshake": 4,
                "uplinkOnly": 1
            }}
        }},
        "system": {{
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }}
    }},
    "routing": {{
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {{
                "inboundTag": [
                    "dns-in"
                ],
                "outboundTag": "dns-out",
                "type": "field"
            }},
            {{
                "ip": [
                    "8.8.8.8"
                ],
                "outboundTag": "direct",
                "port": "53",
                "type": "field"
            }},
            {{
                "domain": [
                    "geosite:category-ir",
                    "domain:.ir"
                ],
                "outboundTag": "direct",
                "type": "field"
            }},
            {{
                "ip": [
                    "geoip:ir",
                    "geoip:private"
                ],
                "outboundTag": "direct",
                "type": "field"
            }},
            {{
                "domain": [
                    "geosite:category-ads-all",
                    "geosite:category-ads-ir"'''
        if isIran == '2':
            if polrn_block == '1': 
                WoW_v2 += ''',
                    "geosite:category-porn"'''
            WoW_v2 += '''
                ],
                "outboundTag": "block",
                "type": "field"
            },
            {
                "network": "tcp,udp",
                "outboundTag": "warp-out",
                "type": "field"
            },
            {
                "network": "tcp,udp",
                "outboundTag": "warp",
                "type": "field"
            }
        ]
    }},
    "stats": {{}}
}}'''
        print(WoW_v2)
        exit()
        
    else:
        os.system('clear')
        hising = f'''
{{
  "outbounds": 
  [
    {{
      "type": "wireguard",
      "tag": "Tel=@arshiacomplus Warp-IR1",
      "local_address": [
          "172.16.0.2/32",
          "{all_key[0]}"
      ],
      "private_key": "{all_key[1]}",
      "peer_public_key": "{all_key[3]}",
      "server": "{best_result[0]}",
      "server_port": {best_result[1]},
      "reserved": {all_key[2]},
      "mtu": 1280'''
        if what != '15' and what != '16':
            hising += ''',
      "fake_packets":"1-3",
      "fake_packets_size":"10-30",
      "fake_packets_delay":"10-30",
      "fake_packets_mode":"m4"'''
        hising += f'''
    }},
    {{
      "type": "wireguard",
      "tag": "Tel=@arshiacomplus Warp-Main1",
      "detour": "Tel=@arshiacomplus Warp-IR1",
      "local_address": [
          "172.16.0.2/32",
          "{all_key2[0]}"
      ],
      "private_key": "{all_key2[1]}",
      "server": "{best_result[0]}",
      "server_port": {best_result[1]},
      "peer_public_key": "{all_key2[3]}",
      "reserved": {all_key2[2]},
      "mtu": 1330'''
        if what != '15' and what != '16':
            hising += ''',
      "fake_packets_mode":"m4"'''
        hising += f'''
    }}
  ]
}}
'''
        print(hising)
        exit()
    if what == "3":
        exit()
    main2_1()

def main2_1():
    global best_result, what
    print()
    try:
        all_key = free_cloudflare_account()
    except Exception as E:
        print('Try again Error =', E)
        exit()
    if what == '7':
        if isIran == '2':
            try:
                all_key2 = free_cloudflare_account()
            except Exception as E:
                print('Try again Error =', E)
                exit()
    else:
        try:
            all_key2 = free_cloudflare_account()
        except Exception as E:
            print('Try again Error =', E)
            exit()
    temp_ip = ''
    temp_port = ''
    temp_c = 0
    if what in ['3', '16']:
        print("\033[0m")
        enter_ip = input('Enter ip with port (Default = Enter for N): ')
        if enter_ip in ['N', 'n', '']:
            best_result = ["162.159.195.166", 908]
        else:
            while enter_ip[temp_c] != ':':
                temp_ip = temp_ip + enter_ip[temp_c]
                temp_c = temp_c + 1
            set_enter_ip = enter_ip.index(":")
            temp_port = enter_ip[set_enter_ip+1:]
            best_result = [temp_ip, int(temp_port)]
    return best_result

def main3(i, how_many):
    global best_result, wire_config_temp, wire_c, wire_p, what
    if wire_p == 0:
         try:
             best_result = main()
         except Exception:
             print("\033[91m")
             print('Try again and choose wireguard without IP scanning')
             print('\033[0m')
             exit()
    os.system('clear')
    if wire_p == 1:
        print(f"please wait, making wireguard config: {wire_c-1}.")
    print('\033[0m')
    if wire_p != 1:
        all_key = free_cloudflare_account()
        time.sleep(5)
        all_key2 = free_cloudflare_account()
        time.sleep(5)
        wire_config_or = f'''
{{
    "type": "wireguard",
    "tag": "Tel=@arshiacomplus Warp-IR{wire_c}",
    "local_address": [
        "172.16.0.2/32",
        "{all_key[0]}"
    ],
    "private_key": "{all_key[1]}",
    "peer_public_key": "{all_key[3]}",
    "server": "{best_result[0]}",
    "server_port": {best_result[1]},
    "reserved": {all_key[2]},
    "mtu": 1280'''
        if what != '17':
            wire_config_or += ''',
    "fake_packets":"1-3",
    "fake_packets_size":"10-30",
    "fake_packets_delay":"10-30",
    "fake_packets_mode":"m4"'''
        wire_config_or += f'''
}},
{{
    "type": "wireguard",
    "tag": "Tel=@arshiacomplus Warp-Main{wire_c}",
    "detour": "Tel=@arshiacomplus Warp-IR{wire_c}",
    "local_address": [
        "172.16.0.2/32",
        "{all_key2[0]}"
    ],
    "private_key": "{all_key2[1]}",
    "server": "{best_result[0]}",
    "server_port": {best_result[1]},
    "peer_public_key": "{all_key2[3]}",
    "reserved": {all_key2[2]},
    "mtu": 1330'''
        if what != '17':
            wire_config_or += ''',
    "fake_packets_mode":"m4"'''
        wire_config_or += '''
}'''
    else:
        all_key = free_cloudflare_account()
        time.sleep(5)
        all_key2 = free_cloudflare_account()
        time.sleep(5)
        wire_config_or = f'''
,{{
    "type": "wireguard",
    "tag": "Tel=@arshiacomplus Warp-IR{wire_c}",
    "local_address": [
        "172.16.0.2/32",
        "{all_key[0]}"
    ],
    "private_key": "{all_key[1]}",
    "peer_public_key": "{all_key[3]}",
    "server": "{best_result[0]}",
    "server_port": {best_result[1]},
    "reserved": {all_key[2]},
    "mtu": 1280'''
        if what != '17':
            wire_config_or += ''',
    "fake_packets":"1-3",
    "fake_packets_size":"10-30",
    "fake_packets_delay":"10-30",
    "fake_packets_mode":"m4"'''
        wire_config_or += f'''
}},
{{
    "type": "wireguard",
    "tag": "Tel=@arshiacomplus Warp-Main{wire_c}",
    "detour": "Tel=@arshiacomplus Warp-IR{wire_c}",
    "local_address": [
        "172.16.0.2/32",
        "{all_key2[0]}"
    ],
    "private_key": "{all_key2[1]}",
    "server": "{best_result[0]}",
    "server_port": {best_result[1]},
    "peer_public_key": "{all_key2[3]}",
    "reserved": {all_key2[2]},
    "mtu": 1330'''
        if what != '17':
            wire_config_or += ''',
    "fake_packets_mode":"m4"'''
        wire_config_or += '''
}'''
    if i == int(how_many)-1:
        os.system('clear')
        upload_to_bashupload(f'''{{
  "outbounds": 
  [{wire_config_temp}
  ]
}}
''')
    else:
        wire_config_temp = wire_config_temp + wire_config_or
    wire_c = wire_c + 1
    wire_p = 1

#############################
# منوی اصلی و بخش‌های اجرایی
#############################
def start_menu():
    os.system('clear')
    check_ipv = check_ipv6()
    rprint(f'ipv4 : [bold red]{check_ipv[0]}[/bold red]\nipv6 : [bold red]{check_ipv[1]}[/bold red]\n')
    options = {
        "1": "scan ip",
        "2": "wireguard for Hiddify",
        "3": "wireguard for Hiddify without ip scanning",
        "4": "wireguard for Hiddify with a sub link",
        "5": "wireguard for v2ray and mahsaNG without noise",
        "6": "wireguard for v2ray and mahsaNG without ip scanning without noise",
        "7": "WoW for v2ray or mahsaNG without noise",
        "8": "WoW for v2ray or mahsaNG in sub link without noise",
        "9": "Add/Delete shortcut",
        "10": "get wireguard.conf",
        "11": "wireguard for nikaNg and MahsaNg with noise",
        "12": "wireguard for nikaNg and MahsaNg without ip scanning with noise",
        "13": "WoW with noise for Nikang or MahsaNg",
        "14": "WoW with noise for Nikang or MahsaNg in sub link",
        "15": "wireguard for Sing-box and Hiddify | old |",
        "16": "wireguard for Sing-box and Hiddify | old | without ip scanning",
        "17": "wireguard for Sing-box and Hiddify | old | with a sub link",
        "00": "info",
        "0": "Exit"
    }
    rprint("[bold red]by Telegram= @arshiacomplus[/bold red]")
    for key, value in options.items():
        rprint(f" [bold yellow]{key}[/bold yellow]: {value}")
    chosen = Prompt.ask("Choose an option", choices=list(options.keys()), default="0")
    return chosen

def get_number_of_configs():
    while True:
        try:
            how_many = int(Prompt.ask('\nHow many configs do you need (2 to 4): '))
            if 2 <= how_many <= 4:
                break
        except ValueError:
            console.print("[bold red]Please enter a valid number![/bold red]", style="red")
    return how_many

def gojo_goodbye_animation():
    frames = [
        "\n\033[94m(＾-＾)ノ\033[0m",
        "\n\033[93m(＾-＾)ノ~~~\033[0m",
        "\n\033[92m(＾-＾)ノ~~~~~~\033[0m",
    ]
    for frame in frames:
        print(frame)
        time.sleep(1)

#############################
# بلوک اصلی اجرای برنامه
#############################
if __name__ == "__main__":
    os.system('clear')
    what = start_menu()
    if what == '1':
        do_you_save = input_p('Do you want to save in a result csv\n', {"1": 'Yes', "2": "No"})
        which = 'n'
        if do_you_save == '1':
            os.system('termux-setup-storage')
            which = input_p('Do you want for bpb panel(with comma) or vahid panel(with enter) in a result csv\n ', {'1': 'bpb panel(with comma)',
                '2': 'vahid panel(with enter)', '3': 'with score', '4': 'clean'})
            if which != "4":
                need_port = input_p('Do you want to save port in result\n ', {'1': 'Yes', '2': 'No'})
            if which == '4':
                which = input_p('Do you want for bpb panel(with comma) or vahid panel(with enter) in a result csv\n ', {'1': 'bpb panel(with comma)',
                    '2': 'vahid panel(with enter)'})
                with open('/storage/emulated/0/result.csv', 'r') as f:
                    b = f.readlines()
                    with open('/storage/emulated/0/clean_result.csv', 'w') as ff:
                        for j in b:
                            if which == '1':
                                ff.write(j[:j.index('|')-1])
                                if j != b[len(b)-1]:
                                    ff.write(',')
                            else:
                                ff.write(j[:j.index('|')-1])
                                ff.write('\n')
                print(' saved in /storage/emulated/0/clean_result.csv !')
                exit()
        main()
    elif what in ['2', '3', '7', '13', '15', '16']:
        if what in ['7', '13']:
            polrn_block = input_p('Do you want to block p@rn sites\n', {"1": "Yes", "2": "No"})
            isIran = input_p('Iran or Germany\n', {"1": "Ip Iran[faster speed]", "2": "Germany[slower speed]"})
        main2()
    elif what in ['4', '17']:
        how_many = get_number_of_configs()
        # در این حالت برای هر کانفیگ، از حلقه استفاده شده است
        for i in range(how_many):
            main3(i, how_many)
    elif what in ['5', '6', '11', '12']:
        api_url = 'http://s9.serv00.com:1074/arshiacomplus/api/wirekey'
        if what in ['5', '11']:
            endpoint_ip_best_result = main()
            endpoint_ip = f"{endpoint_ip_best_result[0]}:{endpoint_ip_best_result[1]}"
        else:
            endpoint_ip = input('Enter ip with port (default = n):')
            if endpoint_ip in ['N', 'n', '']:
                endpoint_ip = "162.159.195.166:878"
            else:
                temp_ip2 = ''
                temp_port2 = ''
                temp_c2 = 0
                while endpoint_ip[temp_c2] != ':':
                    temp_ip2 = temp_ip2 + endpoint_ip[temp_c2]
                    temp_c2 = temp_c2 + 1
                set_enter_ip2 = endpoint_ip.index(":")
                temp_port2 = endpoint_ip[set_enter_ip2+1:]
                endpoint_ip = f"{temp_ip2}:{temp_port2}"
        rprint("[bold green]Please wait, generating WireGuard URL...[/bold green]")
        try:
            config = fetch_config_from_api()
        except Exception as E:
            print('Try again Error =', E)
            exit()
        wireguard_url = generate_wireguard_url(config, endpoint_ip)
        if wireguard_url:
            os.system('clear')
            print(f"\n\n{wireguard_url}\n\n")
        else:
            print("Failed to generate WireGuard URL.")
    elif what in ['8', '14']:
        how_many = get_number_of_configs()
        polrn_block = input_p('Do you want to block p@rn sites\n', {"1": "Yes", "2": "No"})
        isIran = input_p('Iran or Germany\n', {"1": "Ip Iran[faster speed]", "2": "Germany[slower speed]"})
        main2()
    elif what == '9':
        if os.path.exists('/data/data/com.termux/files/usr/etc/bash.bashrc.bak'):
            Delete = input_p('Do you want to Delete shortcut', {"1": "Yes", "2": "No"})
            if Delete == '1':
                os.system('rm /data/data/com.termux/files/usr/etc/bash.bashrc')
                os.rename('/data/data/com.termux/files/usr/etc/bash.bashrc.bak', '/data/data/com.termux/files/usr/etc/bash.bashrc')
                console.print("[bold red]Shortcut Deleted, successful[/bold red]", style="red")
            exit()
        while True:
            name = input("\nEnter a shortcut name : ")
            if not name.isdigit():
                break
            else:
                console.print("\n[bold red]Please enter a valid name![/bold red]", style="red")
        with open('/data/data/com.termux/files/usr/etc/bash.bashrc', 'r') as f2:
            txt = f2.read()
            with open('/data/data/com.termux/files/usr/etc/bash.bashrc.bak', 'w') as f:
                f.write(txt)
        text = f'''
{name}() {{
bash <(curl -fsSL https://raw.githubusercontent.com/arshiacomplus/WarpScanner/main/install.sh)
}}
'''
        with open('/data/data/com.termux/files/usr/etc/bash.bashrc', 'r+') as f:
            content = f.read()
            f.seek(0, 0)
            f.write(text.rstrip('\r\n') + '\n' + content)
        rprint(f"\n[bold green]Please restart your Termux and enter [bold red]{name}[/bold red] to run the script[/bold green]")
    elif what == '10':
        endpoint_ip_best_result = main()
        endpoint_ip = f"{endpoint_ip_best_result[0]}:{endpoint_ip_best_result[1]}"
        try:
            all_key = free_cloudflare_account()
        except Exception as E:
            print('Try again Error =', E)
            exit()
        name_conf = input('\nEnter a name (default: press Enter): ')
        os.system('termux-setup-storage')
        if name_conf == '':
            name_conf = 'acpwire.conf'
        path = f'/storage/emulated/0/{name_conf}.conf'
        with open(path, 'w') as f:
            f.write(f'''[Interface]
PrivateKey = {all_key[1]}
Address = 172.16.0.2/32, {all_key[0]}
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = {all_key[3]}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint_ip}''')
        rprint(f'\n[bold green]{name_conf} saved in {path}[/bold green]')
    elif what == '00':
        info()
    elif what == '0':
        gojo_goodbye_animation()
        time.sleep(1)
        console.print("\n[bold magenta]Exiting... Goodbye![/bold magenta]\n")
        exit()
