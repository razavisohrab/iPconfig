#!/usr/bin/env python3
# ══════════════════════════════════════════════════
#   ASLKEAR — Android Open-App Auto Checker
#   Run in Termux:
#   curl -sL <URL> | python3
# ══════════════════════════════════════════════════
import subprocess, json, os, sys
from urllib.request import urlopen

Y   = "\033[93m"
R   = "\033[91m"
G   = "\033[92m"
C   = "\033[96m"
W   = "\033[0m"
DIM = "\033[90m"
BLD = "\033[1m"

score  = 0
issues = []

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def run2(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except Exception:
        return "", ""

def fetch(url, timeout=10):
    try:
        with urlopen(url, timeout=timeout) as r:
            return r.read().decode()
    except Exception:
        return ""

def head(t):
    print(f"\n{Y}{BLD}{'─'*50}\n  {t}\n{'─'*50}{W}")

def ok(t):
    print(f"  {G}[OK]{W}  {t}")

def warn(t, pts=10):
    global score
    score += pts
    issues.append((t, pts))
    print(f"  {R}[!!]{W}  {t}")

def info(t):
    print(f"  {C} ▸ {W} {t}")

def dim(t):
    print(f"  {DIM}{t}{W}")

# ══════════════════════════════════════════════════
print(f"\n{Y}{BLD}{'═'*50}")
print("   ASLKEAR  •  ANDROID OPEN-APP CHECKER")
print(f"{'═'*50}{W}")

# ─────────────────────────────────────────────────
# DEVICE INFO
# ─────────────────────────────────────────────────
head("0 / Device Info")
model   = run("getprop ro.product.model")
brand   = run("getprop ro.product.brand")
android = run("getprop ro.build.version.release")
sdk     = run("getprop ro.build.version.sdk")
build   = run("getprop ro.build.tags")
info(f"Device  : {brand} {model}")
info(f"Android : {android}  (SDK {sdk})")
info(f"Build   : {build}")

# ─────────────────────────────────────────────────
# 1. ROOT PATH DETECTION
# ─────────────────────────────────────────────────
head("1 / Root Path Detection")

ROOT_PATHS = [
    ('/system/bin/su',                'su binary'),
    ('/system/xbin/su',               'su binary (xbin)'),
    ('/sbin/su',                      'su binary (sbin)'),
    ('/su/bin/su',                    'su binary (su/)'),
    ('/system/app/Superuser.apk',     'Superuser APK'),
    ('/system/framework/XposedBridge.jar', 'Xposed Framework'),
    ('/sys/fs/susfs',                 'SuSFS'),
    ('/dev/magisk',                   'Magisk device'),
]

PRIV_PATHS = [
    ('/data/adb/magisk',   'Magisk', 50),
    ('/data/adb/magisk.db','Magisk DB', 50),
    ('/data/adb/ksud',     'KernelSU', 50),
    ('/data/adb/ksu',      'KernelSU dir', 50),
    ('/data/adb/apatch',   'APatch', 50),
]

found_any = False

for path, label in ROOT_PATHS:
    if os.path.exists(path):
        warn(f"شناسایی شد: {label}  [{path}]", 30)
        found_any = True

for path, label, pts in PRIV_PATHS:
    out, err = run2(f"ls '{path}' 2>&1")
    full = (out + err).lower()
    if 'permission denied' in full or 'not permitted' in full:
        # path EXISTS but blocked — suspicious
        warn(f"مسیر وجود دارد (دسترسی بلاک): {label}  [{path}]", pts)
        found_any = True
    elif 'no such' not in full and out:
        warn(f"شناسایی شد: {label}  [{path}]", pts)
        found_any = True

su_path = run("which su 2>/dev/null")
if su_path:
    warn(f"دستور su در PATH: {su_path}", 25)
    found_any = True

if not found_any:
    ok("مسیر Root / Magisk / KernelSU / APatch شناسایی نشد")

# ─────────────────────────────────────────────────
# 2. SYSTEM PROPERTIES
# ─────────────────────────────────────────────────
head("2 / System Properties")

PROPS = [
    ('ro.build.tags',               'release-keys', False),
    ('ro.debuggable',               '0',            False),
    ('ro.secure',                   '1',            False),
    ('ro.allow.mock.location',      '0',            False),
    ('ro.boot.verifiedbootstate',   'green',        False),
    ('ro.boot.vbmeta.device_state', 'locked',       False),
    ('sys.oem_unlock_allowed',      '0',            False),
    ('persist.zygisk.enable',       '1',            True),
    ('persist.susfs.enabled',       '1',            True),
]

prop_ok = True
for prop, expected, flag_if_eq in PROPS:
    val = run(f"getprop {prop}")
    display = val if val else "(empty)"
    if flag_if_eq:
        if val == expected:
            warn(f"{prop} = {display}  ← مشکوک", 20)
            prop_ok = False
        else:
            dim(f"{prop} = {display}")
    else:
        if val and val != expected:
            warn(f"{prop} = {display}  (باید: {expected})", 20)
            prop_ok = False
        else:
            dim(f"{prop} = {display}")

if prop_ok:
    ok("تمام پراپرتی‌ها سالم هستند")

# ─────────────────────────────────────────────────
# 3. DANGEROUS PACKAGES
# ─────────────────────────────────────────────────
head("3 / Dangerous Package Detection")

DANGER = {
    'com.topjohnwu.magisk':              ('Magisk',          50),
    'io.github.vvb2060.magisk':          ('Magisk Alpha',    50),
    'me.weishu.kernelsu':                ('KernelSU',        50),
    'com.rifsxd.ksunext':                ('KernelSU Next',   50),
    'com.bmax121.apatch':                ('APatch',          50),
    'de.robv.android.xposed.installer':  ('Xposed',          40),
    'io.github.lsposed':                 ('LSPosed',         40),
    'org.lsposed.manager':               ('LSPosed Manager', 40),
    'me.weishu.exposed':                 ('TaiChi',          40),
    'com.noshufou.android.su':           ('SuperUser',       30),
    'eu.chainfire.supersu':              ('SuperSU',         30),
    'com.koushikdutta.superuser':        ('Superuser (CW)',  30),
    'com.mt.mtfile':                     ('MT Manager',      25),
    'com.ztheater.mt':                   ('MT Manager',      25),
    'catch_.me_.if_.you_.can_':          ('GameGuardian',    30),
    'ru.zdevs.zarchiver':                ('ZArchiver',       10),
    'com.lbe.parallel.intl':             ('Parallel Space',  20),
    'com.excelliance.dualaid':           ('Dual Space',      20),
    'com.lexa.fakegps':                  ('Fake GPS',        20),
    'com.incorporateapps.fakegps.fre':   ('Fake GPS Free',   20),
}

pkg_list = run("pm list packages 2>/dev/null")
found_pkgs = []
for pkg, (name, pts) in DANGER.items():
    if pkg in pkg_list:
        found_pkgs.append((name, pkg, pts))

if found_pkgs:
    for name, pkg, pts in found_pkgs:
        warn(f"{name}  [{pkg}]", pts)
else:
    ok("پکیج مشکوک شناسایی نشد")

# ─────────────────────────────────────────────────
# 4. MOUNT ANALYSIS
# ─────────────────────────────────────────────────
head("4 / Mount Namespace Analysis")

mounts_raw = run("cat /proc/mounts 2>/dev/null")
if not mounts_raw:
    mounts_raw = run("cat /proc/self/mountinfo 2>/dev/null")

mount_lines = mounts_raw.splitlines()
count = len(mount_lines)
info(f"تعداد Mount: {count}")

if count > 200:
    warn(f"Mount count بسیار بالا: {count} — احتمال بالای Magisk Magic Mount", 50)
elif count > 130:
    warn(f"Mount count مشکوک: {count}", 25)
else:
    ok(f"Mount count عادی: {count}")

suspicious = []
for line in mount_lines:
    l = line.lower()
    if any(x in l for x in ['overlay', '/data/adb', 'magisk', 'susfs', 'worker']):
        suspicious.append(line.strip())

if suspicious:
    for m in suspicious[:4]:
        warn(f"Mount مشکوک: {m[:70]}", 20)
else:
    ok("OverlayFS / Magisk mount شناسایی نشد")

# ─────────────────────────────────────────────────
# 5. SELINUX
# ─────────────────────────────────────────────────
head("5 / SELinux Status")

selinux = run("cat /sys/fs/selinux/enforce 2>/dev/null")
if not selinux:
    selinux = run("getenforce 2>/dev/null")

info(f"SELinux: {selinux or '(unreadable)'}")
if selinux in ('0', 'Permissive', 'permissive'):
    warn("SELinux غیرفعال — Permissive (Root احتمالی)", 30)
elif selinux in ('1', 'Enforcing', 'enforcing'):
    ok("SELinux فعال — Enforcing")
else:
    dim("وضعیت SELinux نامشخص")

# ─────────────────────────────────────────────────
# 6. IP + LOCATION + VPN
# ─────────────────────────────────────────────────
head("6 / IP — Location — VPN Check")

final_ip = ""
raw = fetch("http://ip-api.com/json?fields=status,message,country,countryCode,city,isp,org,proxy,hosting,query")
if raw:
    try:
        d = json.loads(raw)
        if d.get('status') == 'success':
            final_ip = d.get('query', '')
            info(f"IP      : {C}{final_ip}{W}")
            info(f"Country : {d.get('country','?')} / {d.get('city','?')}")
            info(f"ISP     : {d.get('isp','?')}")
            if d.get('proxy') or d.get('hosting'):
                warn("VPN / Proxy شناسایی شد — مجاز نیست", 40)
            elif d.get('countryCode') == 'IR':
                ok("ایران تأیید شد — بدون VPN")
            else:
                warn(f"کشور: {d.get('country','?')} — احتمال VPN یا خارج از ایران", 40)
        else:
            warn(f"خطا: {d.get('message','unknown')}", 0)
    except Exception:
        warn("خطا در پارس پاسخ IP", 0)
else:
    warn("اتصال به سرور بررسی ممکن نبود", 0)

# ─────────────────────────────────────────────────
# 7. VPN INTERFACE CHECK
# ─────────────────────────────────────────────────
head("7 / VPN Interface Detection")

ifaces = run("ip addr show 2>/dev/null || ifconfig 2>/dev/null")
VPN_IFACES = ['tun0','tun1','wg0','wg1','ppp0','ipsec0','vpn0']
found_iface = [i for i in VPN_IFACES if i in ifaces]

if found_iface:
    for iface in found_iface:
        warn(f"VPN Interface فعال: {iface}", 35)
else:
    ok("VPN Interface شناسایی نشد")

# ─────────────────────────────────────────────────
# 8. DNS CHECK + DNS CHANGER
# ─────────────────────────────────────────────────
head("8 / DNS Check — DNS Changer Detect")

dns_raw = run("nslookup google.com 2>/dev/null")
if dns_raw:
    for line in dns_raw.splitlines()[:6]:
        dim(line)

DNS_CHANGERS = {
    'Shecan':      ['178.22.122.100', '185.51.200.2'],
    'Electro':     ['78.157.42.100',  '78.157.42.101'],
    '403.online':  ['10.202.10.202',  '10.202.10.102'],
    'Radar':       ['10.202.10.10',   '10.202.10.11'],
    'Begzar':      ['185.55.226.26',  '185.55.225.25'],
    'Google DNS':  ['8.8.8.8',        '8.8.4.4'],
    'Cloudflare':  ['1.1.1.1',        '1.0.0.1'],
}

dc_found = None
for name, ips in DNS_CHANGERS.items():
    for ip in ips:
        if ip in dns_raw:
            dc_found = (name, ip)
            break

if dc_found:
    warn(f"DNS تغییر یافته: {dc_found[0]} ({dc_found[1]}) — مجاز نیست", 25)
else:
    ok("DNS Changer شناسایی نشد")

# ─────────────────────────────────────────────────
# 9. DNS LEAK TEST
# ─────────────────────────────────────────────────
head("9 / DNS Leak Test")

cf = fetch("https://1.1.1.1/cdn-cgi/trace")
cf_ip = next((l.split('=')[1] for l in cf.splitlines()
              if l.startswith('ip=')), '') if cf else ''

if cf_ip:
    info(f"Cloudflare edge: {cf_ip}")
    if final_ip and cf_ip != final_ip:
        warn("IP ناهماهنگ — احتمال DNS Leak", 20)
    else:
        ok("DNS Leak شناسایی نشد")
else:
    ok("DNS Leak شناسایی نشد")

# ══════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════
print(f"\n{Y}{BLD}{'═'*50}{W}")
print(f"{Y}{BLD}   RESULT SUMMARY{W}")
print(f"{Y}{'─'*50}{W}")

if score == 0:
    lvl, col = "✅  PASS", G
    note = "هیچ مشکلی شناسایی نشد — اوپن‌اپ مجاز است"
elif score < 30:
    lvl, col = "⚠️   LOW RISK", Y
    note = "موارد جزئی — بررسی دستی توصیه می‌شود"
elif score < 60:
    lvl, col = "⚠️   MEDIUM RISK", Y
    note = "مشکل شناسایی شد — نیاز به بررسی بیشتر"
else:
    lvl, col = "⛔  CRITICAL", R
    note = "دستگاه مشکوک — اوپن‌اپ مجاز نیست"

print(f"\n  {col}{BLD}{lvl}  — امتیاز: {score}{W}")
print(f"  {col}{note}{W}\n")

if issues:
    print(f"  {R}{BLD}موارد شناسایی‌شده:{W}")
    for txt, pts in issues:
        print(f"  {R}  • {txt}  (+{pts}){W}")

print(f"\n{Y}{BLD}{'═'*50}{W}")
print(f"{Y}{BLD}   CHECK COMPLETE — ASLKEAR{W}")
print(f"{Y}{BLD}{'═'*50}{W}\n")
