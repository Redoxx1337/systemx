import re
import socket
from datetime import datetime

import requests

HEADERS = {"User-Agent": "Mozilla/5.0"}


# ============ ПАРСЕР ============
def is_ip(s: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", s.strip()))


def is_domain(s: str) -> bool:
    return bool(re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,}", s.lower().strip()))


def resolve(target: str) -> str:
    """Домен -> IP."""
    try:
        return socket.gethostbyname(target)
    except Exception:
        return ""


# ============ ИСТОЧНИКИ ============


def ip_api(ip: str) -> dict:
    """ip-api.com — гео, провайдер, ASN, координаты. Без ключа, 45/мин."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            },
            headers=HEADERS,
            timeout=15,
        )
        d = r.json()
        if d.get("status") == "success":
            return {"found": True, **d}
        return {"found": False, "error": d.get("message", "failed")}
    except Exception as e:
        return {"found": False, "error": str(e)}


def ip_whois(ip: str) -> dict:
    """RDAP — официальный WHOIS-API. Без ключа."""
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return {"found": False}
        d = r.json()
        out = {
            "found": True,
            "handle": d.get("handle"),
            "name": d.get("name"),
            "country": d.get("country"),
            "startAddress": d.get("startAddress"),
            "endAddress": d.get("endAddress"),
            "type": d.get("type"),
            "parentHandle": d.get("parentHandle"),
            "events": {},
            "entities": [],
        }
        for e in d.get("events", []):
            out["events"][e.get("eventAction")] = e.get("eventDate")
        for ent in d.get("entities", []):
            vcard = ent.get("vcardArray", [])
            name = None
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        name = item[3]
            out["entities"].append(
                {
                    "handle": ent.get("handle"),
                    "roles": ent.get("roles", []),
                    "name": name,
                }
            )
        return out
    except Exception as e:
        return {"found": False, "error": str(e)}


def ip_rdns(ip: str) -> str:
    """Reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def ip_bgp(ip: str) -> dict:
    """BGP-инфа через bgpview.io — без ключа."""
    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return {"found": False}
        d = r.json()
        if d.get("status") != "ok":
            return {"found": False}
        data = d.get("data", {})
        prefixes = data.get("prefixes", [])
        out = {"found": True, "rir": data.get("rir_allocation", {}), "prefixes": []}
        for p in prefixes:
            out["prefixes"].append(
                {
                    "prefix": p.get("prefix"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "asn": p.get("asn", {}).get("asn"),
                    "asn_name": p.get("asn", {}).get("name"),
                    "asn_desc": p.get("asn", {}).get("description"),
                    "country": p.get("asn", {}).get("country_code"),
                }
            )
        return out
    except Exception as e:
        return {"found": False, "error": str(e)}


def ip_threat(ip: str) -> dict:
    """Проверка на черные листы через blackbox (без ключа, 429 без регистрации)."""
    try:
        r = requests.get(
            f"https://blackbox.ipinfo.app/lookup/{ip}", headers=HEADERS, timeout=15
        )
        if r.status_code == 200:
            return {
                "found": True,
                "malicious": r.text.strip() == "Y",
                "raw": r.text.strip(),
            }
        return {"found": False}
    except Exception:
        return {"found": False}


def ip_ssl(ip: str) -> dict:
    """SSL-сертификат по IP (если есть 443)."""
    import ssl

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return {
                    "found": True,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "SAN": [x[1] for x in cert.get("subjectAltName", [])],
                }
    except Exception as e:
        return {"found": False, "error": str(e)}


# ============ ПОРТЫ ============
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}


def scan_ports(ip: str, ports: dict = None, timeout: float = 1.0) -> list:
    """Быстрый скан портов через socket."""
    import concurrent.futures

    ports = ports or COMMON_PORTS
    results = []

    def check(port):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return {"port": port, "service": ports[port], "open": True}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(check, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                results.append(res)
    return sorted(results, key=lambda x: x["port"])


# ============ ВЫВОД ============
def print_header(text):
    print(f"\n{'─'*60}")
    print(f"  {text}")
    print(f"{'─'*60}")


def print_geo(d: dict):
    if not d.get("found"):
        return
    print_header("🌍 ГЕОЛОКАЦИЯ")
    print(f"   IP:          {d.get('query')}")
    if d.get("country"):
        print(f"   Страна:      {d['country']} ({d.get('countryCode', '?')})")
    if d.get("regionName"):
        print(f"   Регион:      {d['regionName']} ({d.get('region', '?')})")
    if d.get("city"):
        print(f"   Город:       {d['city']}")
    if d.get("zip"):
        print(f"   Индекс:      {d['zip']}")
    if d.get("lat") is not None and d.get("lon") is not None:
        print(f"   Координаты:  {d['lat']}, {d['lon']}")
        print(f"   🗺️  Карта:    https://www.google.com/maps?q={d['lat']},{d['lon']}")
        print(
            f"   🗺️  OSM:      https://www.openstreetmap.org/?mlat={d['lat']}&mlon={d['lon']}"
        )
    if d.get("timezone"):
        print(f"   Часовой пояс: {d['timezone']}")


def print_net(d: dict):
    if not d.get("found"):
        return
    print_header("🛰️  ПРОВАЙДЕР / СЕТЬ")
    if d.get("isp"):
        print(f"   ISP:         {d['isp']}")
    if d.get("org"):
        print(f"   Организация: {d['org']}")
    if d.get("as"):
        print(f"   AS:          {d['as']}")
    if d.get("asname"):
        print(f"   ASN name:    {d['asname']}")
    if d.get("reverse"):
        print(f"   Reverse DNS: {d['reverse']}")
    flags = []
    if d.get("mobile"):
        flags.append("📱 мобильный")
    if d.get("proxy"):
        flags.append("🕵️ прокси/VPN")
    if d.get("hosting"):
        flags.append("🖥️ хостинг/дата-центр")
    if flags:
        print(f"   Флаги:       {', '.join(flags)}")


def print_whois(d: dict):
    if not d.get("found"):
        return
    print_header("📋 WHOIS (RDAP)")
    for k, label in [
        ("handle", "Handle"),
        ("name", "Название"),
        ("country", "Страна"),
        ("type", "Тип"),
        ("startAddress", "Начало диапазона"),
        ("endAddress", "Конец диапазона"),
        ("parentHandle", "Родительский"),
    ]:
        if d.get(k):
            print(f"   {label}: {d[k]}")
    if d.get("events"):
        print(f"   События:")
        for k, v in d["events"].items():
            print(f"      {k}: {v}")
    if d.get("entities"):
        print(f"   Организации:")
        for e in d["entities"][:5]:
            roles = ",".join(e.get("roles", []))
            print(f"      • {e.get('name') or e.get('handle')} [{roles}]")


def print_bgp(d: dict):
    if not d.get("found"):
        return
    print_header("🌐 BGP / ASN")
    rir = d.get("rir", {})
    if rir.get("rir"):
        print(f"   RIR:         {rir['rir']}")
    if rir.get("country_code"):
        print(f"   Страна:      {rir['country_code']}")
    for p in d.get("prefixes", [])[:5]:
        print(f"\n   AS{p.get('asn')} — {p.get('asn_name')}")
        if p.get("asn_desc"):
            print(f"      Описание: {p['asn_desc']}")
        if p.get("prefix"):
            print(f"      Префикс:  {p['prefix']}")
        if p.get("name"):
            print(f"      Сеть:     {p['name']}")


def print_threat(d: dict):
    if not d.get("found"):
        return
    print_header("🚨 РЕПУТАЦИЯ")
    if d.get("malicious"):
        print(f"   ⚠️  В ЧЁРНЫХ СПИСКАХ")
    else:
        print(f"   ✅ Чистый")


def print_ssl(d: dict):
    if not d.get("found"):
        return
    print_header("🔐 SSL СЕРТИФИКАТ")
    if d.get("subject"):
        print(f"   Subject:  {d['subject']}")
    if d.get("issuer"):
        print(f"   Issuer:   {d['issuer']}")
    if d.get("notBefore"):
        print(f"   Выдан:    {d['notBefore']}")
    if d.get("notAfter"):
        print(f"   Истекает: {d['notAfter']}")
    if d.get("SAN"):
        print(f"   SAN-домены:")
        for s in d["SAN"][:15]:
            print(f"      • {s}")


def print_ports(ports: list):
    if not ports:
        return
    print_header(f"🔓 ОТКРЫТЫЕ ПОРТЫ ({len(ports)})")
    for p in ports:
        print(f"   {p['port']:^5}  {p['service']}")


# ============ ГЛАВНАЯ ============
def check(target: str):
    target = target.strip()
    # Резолвим домен
    if is_domain(target):
        ip = resolve(target)
        if not ip:
            print(f"❌ Не удалось резолвить {target}")
            return
        print(f"\n{'='*60}")
        print(f"🌐 {target} → {ip}")
        print(f"{'='*60}")
    elif is_ip(target):
        ip = target
        print(f"\n{'='*60}")
        print(f"🌐 IP: {ip}")
        print(f"{'='*60}")
    else:
        print("❌ Введи корректный IP или домен")
        return
    # Reverse DNS
    rdns = ip_rdns(ip)
    if rdns:
        print(f"   Reverse:  {rdns}")
    # Гео
    geo = ip_api(ip)
    print_geo(geo)
    print_net(geo)
    # WHOIS
    whois = ip_whois(ip)
    print_whois(whois)
    # BGP
    bgp = ip_bgp(ip)
    print_bgp(bgp)
    # Репутация
    threat = ip_threat(ip)
    print_threat(threat)
    # SSL
    ssl_info = ip_ssl(ip)
    print_ssl(ssl_info)
    # Порты
    print(f"\n🔍 Сканирую порты...")
    ports = scan_ports(ip)
    print_ports(ports)
    print(f"\n{'='*60}")
    print(f"✅ ГОТОВО")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    target = input("IP / домен: ").strip()
    check(target)
