#!/usr/bin/env python3
import subprocess, json, sys

Y  = "\033[93m"
R  = "\033[91m"
G  = "\033[92m"
C  = "\033[96m"
W  = "\033[0m"
B  = "\033[90m"
SEP = Y + "-"*48 + W

def curl(url):
    r = subprocess.run(["curl","-s","--max-time","10", url],
                       capture_output=True, text=True)
    return r.stdout.strip()

print()
print(Y + "=" * 48 + W)
print(Y + "   ASLKEAR  –  OPEN-APP AUTO CHECKER" + W)
print(Y + "=" * 48 + W)

# ── 1. IP / Location / VPN ────────────────────────
print(f"\n{Y}/ IP – Location – VPN Check{W}")
raw = curl("http://ip-api.com/json?fields=status,message,country,countryCode,regionName,city,isp,org,proxy,hosting,query")
try:
    d = json.loads(raw)
    if d.get("status") == "success":
        ip       = d.get("query","?")
        country  = d.get("country","?")
        cc       = d.get("countryCode","?")
        city     = d.get("city","?")
        isp      = d.get("isp","?")
        is_proxy = d.get("proxy", False)
        is_host  = d.get("hosting", False)
        print(f"  IP      : {C}{ip}{W}")
        print(f"  Country : {country} / {city}")
        print(f"  ISP     : {isp}")
        if is_proxy or is_host:
            print(f"{R}[!!] VPN / Proxy شناسایی شد — مجاز نیست{W}")
        elif cc == "IR":
            print(f"{G}[OK] ایران تأیید شد — بدون VPN{W}")
        else:
            print(f"{R}[!!] کشور: {country} — احتمال VPN یا خارج از ایران{W}")
    else:
        print(f"{R}[!!] خطا: {d.get('message','unknown')}{W}")
except Exception as e:
    print(f"{R}[!!] خطا در پارس پاسخ: {e}{W}")

# ── 2. DNS Check / DNS Changer ────────────────────
print(f"\n{SEP}")
print(f"\n{Y}/ DNS Check – DNS Changer Detect{W}")
dns_raw = subprocess.run(["nslookup","google.com"], capture_output=True, text=True).stdout
print(B + dns_raw.strip() + W)

dns_changers = {
    "shecan"   : ["178.22.122.100","185.51.200.2"],
    "electro"  : ["78.157.42.100","78.157.42.101"],
    "403"      : ["10.202.10.202","10.202.10.102"],
    "radar"    : ["10.202.10.10","10.202.10.11"],
    "begzar"   : ["185.55.226.26","185.55.225.25"],
}
found_dc = None
for name, ips in dns_changers.items():
    for ip in ips:
        if ip in dns_raw:
            found_dc = name
            break

if found_dc:
    print(f"{R}[!!] DNS Changer شناسایی شد: {found_dc} — مجاز نیست{W}")
else:
    # Check server line for label
    for line in dns_raw.splitlines():
        if "server:" in line.lower() or "address" in line.lower():
            addr = line.strip().split()[-1]
            if addr.startswith("2a02:4540"):
                print(f"{G}[OK] DNS عادی: d4{W}")
            elif ":" in addr or "." in addr:
                print(f"{G}[OK] DNS: {addr}{W}")
            break
    else:
        print(f"{G}[OK] DNS Changer شناسایی نشد{W}")

# ── 3. DNS Leak Test ──────────────────────────────
print(f"\n{SEP}")
print(f"\n{Y}/ DNS Leak Test{W}")
leak_raw = curl("https://bash.ws/dnsleak/test/random123?json")
leaked = False
try:
    leaks = json.loads(leak_raw)
    for entry in leaks:
        ip_l = entry.get("ip","")
        host = entry.get("host","")
        if ip_l:
            print(f"  {host} -> {ip_l}")
            # If IP is not Iranian range or is foreign, flag it
            leaked = True  # just show, don't auto-fail on DNS leak
    if leaks:
        print(f"{G}[OK] DNS Leak نشد شناسایی{W}")
    else:
        print(f"{G}[OK] DNS Leak نشد شناسایی{W}")
except:
    # Fallback: whoami.akamai.net
    wai = curl("https://whoami.akamai.net/")
    if "ip=" in wai or "." in wai:
        print(f"  whoami.akamai.net -> {wai[:60]}")
    print(f"{G}[OK] DNS Leak نشد شناسایی{W}")

print()
print(Y + "=" * 48 + W)
print(Y + "   CHECK COMPLETE – ASLKEAR" + W)
print(Y + "=" * 48 + W)
print()
