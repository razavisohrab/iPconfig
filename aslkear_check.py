#!/usr/bin/env python3
# ASLKEAR - iOS Open-App Auto Checker
# Run in A-Shell: python3 aslkear_check.py
import urllib.request, json, subprocess

R="\033[91m"; G="\033[92m"; Y="\033[93m"
C="\033[96m"; B="\033[1m";  E="\033[0m"

SEP  = "─" * 42
SEP2 = "═" * 42

def head(t): print(f"\n{Y}{B}{SEP}\n  {t}\n{SEP}{E}")
def ok(t):   print(f"  {G}[OK]  {t}{E}")
def warn(t): print(f"  {R}[!!]  {t}{E}")
def info(t): print(f"  {C} >   {t}{E}")

print(f"\n{Y}{B}{SEP2}")
print("   ASLKEAR  -  OPEN-APP AUTO CHECKER")
print(f"{SEP2}{E}")

# 1. IP + Location + VPN
head("1 / IP - Location - VPN Check")
try:
    with urllib.request.urlopen("https://ipinfo.io/json", timeout=10) as r:
        d = json.loads(r.read())
    ip=d.get("ip","?"); city=d.get("city","?"); region=d.get("region","?")
    country=d.get("country","?"); org=d.get("org","?")
    info(f"IP      : {B}{ip}{E}")
    info(f"City    : {city}, {region}, {country}")
    info(f"ISP/Org : {org}")
    vpn_kw=["vpn","proxy","hosting","server","cloud","datacenter",
            "digitalocean","linode","vultr","ovh","hetzner",
            "mullvad","nordvpn","expressvpn","tor","relay","tunnel"]
    if any(k in org.lower() for k in vpn_kw):
        warn(f"ISP مشکوک به VPN/Proxy! - {org}")
    else:
        ok("IP پاک است - VPN شناسایی نشد")
except Exception as e:
    warn(f"Error: {e}")

# 2. DNS Check
head("2 / DNS Check - DNS Changer Detect")
try:
    r=subprocess.run(["nslookup","google.com"],capture_output=True,text=True,timeout=10)
    server=""
    for ln in r.stdout.splitlines():
        if ln.strip(): info(ln)
        if "Server" in ln: server=ln.split(":")[-1].strip()
    if server:
        bad=["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","94.140","208.67","185.228"]
        if any(server.startswith(x) for x in bad):
            warn(f"DNS تغییر یافته: {server} - DNS Changer احتمالی!")
        else:
            ok(f"DNS سرور عادی: {server}")
except Exception as e:
    warn(f"Error: {e}")

# 3. DNS Leak
head("3 / DNS Leak Test")
try:
    leaked=[]
    for host in ["whoami.akamai.net","o-o.myaddr.l.google.com"]:
        r=subprocess.run(["nslookup",host],capture_output=True,text=True,timeout=8)
        for ln in r.stdout.splitlines():
            if "Address" in ln and "#" not in ln:
                ip_f=ln.split(":")[-1].strip()
                info(f"{host} -> {ip_f}")
                leaked.append(ip_f)
    if len(set(leaked))<=1:
        ok("DNS Leak شناسایی نشد")
    else:
        warn("چندین DNS سرور شناسایی شد - احتمال Leak!")
except Exception as e:
    warn(f"Error: {e}")

print(f"\n{Y}{B}{SEP2}")
print("        CHECK COMPLETE - ASLKEAR")
print(f"{SEP2}{E}\n")
