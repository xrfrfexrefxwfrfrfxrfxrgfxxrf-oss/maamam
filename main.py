import os
import platform
import socket
import getpass
import psutil
import hashlib
import base64
import requests
import whois

API_TOKEN = "c581428172c6ac"

# ---------------- UTILITY ----------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def print_os_logo():
    system = platform.system()

    # Windows ASCII Logo
    if system == "Windows":
        print("\033[32m" + r"""
  _       __    __           _           _       
 | |      \ \  / /          | |         | |      
 | | ___   \ \/ /__ _ __ ___| |__   __ _ | |_ ___ 
 | |/ _ \   \  / _ \ '__/ _ \ '_ \ / _` || __/ _ \
 | |  __/   | |  __/ | |  __/ | | | (_| || ||  __/
 |_|\___|   |_|\___|_|  \___|_| |_|\__,_| \__\___|
""")

    # macOS ASCII Logo
    elif system == "Darwin":
        print("\033[32m" + r"""
  __  __    _    _____   ____     _____ _______ 
 |  \/  |  / \  | ____| |  _ \   | ____| ____|
 | |\/| | / _ \ |  _|   | |_) |  |  _|  |  _|  
 | |  | |/ ___ \| |___  |  __/   | |___ | |___ 
 |_|  |_/_/   \_\_____| |_|      |_____|______|
""")

    # Linux ASCII Logo
    elif system == "Linux":
        print("\033[32m" + r"""
   _      _     _           _         _     _   
  | |    (_)   | |         | |       | |   (_)  
  | |     _ ___| |_ ___    | |__  ___| |__  _ __
  | |    | / __| __/ _ \   | '_ \/ __| '_ \| '__|
  | |____| \__ \ ||  __/   | |_) \__ \ | | | |   
  |______|_|___/\__\___|   |_.__/|___/_| |_|_|   
""")
    else:
        print("Unknown OS")

def banner():
    print_os_logo()
    print("\033[32m" + r"""
          CYBER TOOLKIT V7 HACKER MODE
--------------------------------------------------------
ip | fetch ip | publicip
subdomains | hash | base64
neofetch | dns | status
headers | ports | clear | exit
--------------------------------------------------------
osint | osint email
--------------------------------------------------------
\033[39m""")  # Reset to default color

def input_command():
    return input("\033[32mcyber> \033[39m")

# ---------------- SYSTEM ----------------
def neofetch():
    print("User:", getpass.getuser())
    print("Hostname:", socket.gethostname())
    print("OS:", platform.system(), platform.release())
    print("CPU:", platform.processor())
    print("RAM:", round(psutil.virtual_memory().total / (1024**3),2), "GB")
    print("Python:", platform.python_version())
    print()

# ---------------- IP ----------------
def fetch_ip_info(ip="me"):
    try:
        if ip == "me":
            url = "https://api.ipinfo.io/lite/me"
        else:
            url = f"https://api.ipinfo.io/lite/{ip}"

        headers = {"Authorization": f"Bearer {API_TOKEN}"}
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code != 200:
            print("API ERROR:", r.status_code)
            print(r.text)
            return

        data = r.json()

        print("\n------ IP INFO ------")
        for k,v in data.items():
            print(f"{k}: {v}")

        if "loc" in data:
            print("Google Maps:",
                  f"https://www.google.com/maps?q={data['loc']}")

        try:
            host = socket.gethostbyaddr(data.get("ip"))[0]
            print("Reverse DNS:", host)
        except:
            print("Reverse DNS: N/A")

        print("---------------------\n")

    except Exception as e:
        print(f"IP fetch failed: {e}")

def public_ip():
    try:
        ip = requests.get("https://api.ipify.org").text
        print("Public IP:", ip)
    except Exception as e:
        print(f"Public IP fetch failed: {e}")

# ---------------- OSINT ----------------
def osint_email():
    email = input("Email: ")
    print("\nChecking Email footprint...\n")

    platforms = [
        f"https://github.com/{email.split('@')[0]}",
        f"https://twitter.com/{email.split('@')[0]}",
        f"https://instagram.com/{email.split('@')[0]}",
        f"https://www.reddit.com/user/{email.split('@')[0]}",
        f"https://t.me/{email.split('@')[0]}",
        f"https://www.linkedin.com/in/{email.split('@')[0]}",
        f"https://stackoverflow.com/users/{email.split('@')[0]}",
    ]

    for site in platforms:
        try:
            r = requests.get(site)
            print(f"[{'FOUND' if r.status_code == 200 else 'NOT FOUND'}] {site}")
        except Exception as e:
            print(f"[ERROR] {site}: {e}")

def subdomain_lookup():
    domain = input("Domain: ")
    subs = ["www", "mail", "ftp", "dev", "api", "test", "blog", "shop", "staging"]
    print("\nChecking subdomains...\n")
    for sub in subs:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            print(f"[FOUND] {full} -> {ip}")
        except Exception as e:
            print(f"[ERROR] {full}: {e}")
    print()

def whois_lookup():
    domain = input("Domain: ")
    try:
        w = whois.whois(domain)
        print(f"Domain Info for {domain}:")
        for key, value in w.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(f"Whois lookup failed: {e}")

def dns_lookup():
    domain = input("Domain: ")
    try:
        ip = socket.gethostbyname(domain)
        print("IP:", ip)
    except Exception as e:
        print(f"DNS lookup failed: {e}")

def port_scan():
    print("\nScanning localhost ports 1-1024...\n")
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                print(f"Port {port} OPEN")
        except Exception as e:
            print(f"Port scan failed on port {port}: {e}")
        finally:
            s.close()

# ---------------- MAIN ----------------
def run_osint():
    print("\nOSINT Tools: Choose one of the following:\n")
    print("1. Email OSINT")
    print("2. Subdomain Lookup")
    print("3. DNS Lookup")
    print("4. Whois Lookup")
    print("5. Port Scan")
    
    choice = input("\nEnter the number of the OSINT tool: ")

    if choice == "1":
        osint_email()
    elif choice == "2":
        subdomain_lookup()
    elif choice == "3":
        dns_lookup()
    elif choice == "4":
        whois_lookup()
    elif choice == "5":
        port_scan()
    else:
        print("Invalid choice. Try again.")

def main():
    clear()
    banner()

    while True:
        try:
            cmd = input_command().lower()

            if cmd == "exit":
                break
            elif cmd == "clear":
                clear(); banner()
            elif cmd == "neofetch":
                neofetch()
            elif cmd == "ip":
                fetch_ip_info("me")
            elif cmd == "fetch ip":
                ip = input("Enter IP: ")
                fetch_ip_info(ip)
            elif cmd == "publicip":
                public_ip()
            elif cmd == "osint":
                run_osint()
            elif cmd == "osint email":
                osint_email

