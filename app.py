#!/usr/bin/env python3
"""readall — автономный сервис сбора, валидации и публикации VLESS и прокси.

Модуль 1: VPN строго VLESS (vless://), приоритет Reality/TLS.
  - SS (ss://) и VMess (vmess://) полностью исключены.
  - Динамический поиск через GitHub Search API, мёртвые источники отбрасываются.
  - Geo: страна узла определяется по IP (ip-api.com, кэш в state.json).
    Blacklist: RU, UA, CN, IR, BY, KZ, UZ, AM, AZ, KG, TJ, MD — полностью исключены.
  - Порядок подписки строгий: FI 6, US 6, DE 6, PL 6,
    затем 6 редких стран по 1 узлу (всего 30). Имена: "🇫🇮 FI | Fast 01" и т.п.
  - Ровно 6 на страну, не больше не меньше: если после первого прохода
    проверки какая-то страна не набрала 6, проверяются остальные кандидаты,
    а если и этого мало — добирается из прошлого пула (рабочие узлы той же
    страны). Публикуется всегда полный набор 30 узлов.
  - Редкие страны — случайные, меняются ровно раз в сутки (seed = дата UTC,
    хранится в state.json как rare_date/rare_countries). Если редкая страна
    перестаёт отвечать (монитор, 2 проверки подряд), она заменяется на
    другую случайную страну сразу, не дожидаясь суток.
  - Проверка: TCP + TLS/Reality handshake, таймаут 3 с.
  - Скорость: реальный замер через Xray-core — скачивание 2 МБ через
    VLESS-туннель узла (speed.cloudflare.com), порог 5 Мбит/с: медленнее —
    узел улетает и заменяется из резерва той же страны. Замер делается
    при каждом полном цикле (раз в 30 минут) и разовой командой
    --speed-check для текущего пула. 5-минутный мониторинг по-прежнему
    ловит мёртвые узлы по handshake-задержке: задержка >2000 мс или рост
    в 3+ раза от базовой — 2 проверки подряд = медленный узел.
  - Sticky Pool + 5-минутный мониторинг: узел заменяется только после
    2 неудач подряд (таймаут/ошибка) или 2 медленных проверок подряд.
    Замена — из резерва той же страны, если есть, иначе из любого резерва.
    При замене подписка сразу коммитится в GitHub.

Модуль 2: Прокси HTTP / SOCKS5
  - Geo-фильтр по тому же blacklist, сортировка по пингу (задержке проверки).
  - http_proxies.txt / socks5_proxies.txt, по одному ip:port на строку.

Публикация: GITHUB_TOKEN из /opt/readall/.env, GitHub Contents API.
Полный цикл — каждые 1800 с, мониторинг пула — каждые 300 с.
"""
import asyncio
import base64
import html
import json
import logging
import os
import random
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlparse

import aiohttp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("readall")

OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "/opt/readall/output"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/opt/readall/state.json"))
INTERVAL = int(os.environ.get("COLLECT_INTERVAL", "1800"))
MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL", "300"))
MAX_PROXY = int(os.environ.get("MAX_PROXIES", "200"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "foto-co-zvezdoy/readall")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")

# Порог медленного узла: задержка handshake >2000 мс
# или рост в 3+ раза от базовой.
SLOW_MS = 2000.0
SLOW_RATIO = 3.0

# Реальный замер скорости через Xray-core: скачивание 2 МБ через туннель.
XRAY_BIN = os.environ.get("XRAY_BIN", "/opt/readall/xray/xray")
SPEED_MIN_MBPS = float(os.environ.get("SPEED_MIN_MBPS", "5"))
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=2000000"
SPEED_TEST_TIMEOUT = 15
SPEED_CONCURRENCY = 4

BLACKLIST = {"RU", "UA", "CN", "IR", "BY", "KZ", "UZ", "AM", "AZ", "KG", "TJ", "MD"}
MAIN_COUNTRIES = ["FI", "US", "DE", "PL"]
PER_COUNTRY = 6
RARE_COUNT = 6

FLAGS = {
    "DE": "🇩🇪", "FI": "🇫🇮", "PL": "🇵🇱", "NL": "🇳🇱", "SE": "🇸🇪", "US": "🇺🇸",
    "HR": "🇭🇷", "CH": "🇨🇭", "AT": "🇦🇹", "CZ": "🇨🇿", "ES": "🇪🇸", "GB": "🇬🇧",
    "JP": "🇯🇵", "FR": "🇫🇷", "IT": "🇮🇹", "CA": "🇨🇦", "NO": "🇳🇴", "DK": "🇩🇰",
    "IE": "🇮🇪", "PT": "🇵🇹", "BE": "🇧🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
    "LT": "🇱🇹", "RO": "🇷🇴", "GR": "🇬🇷", "HU": "🇭🇺", "SK": "🇸🇰", "SI": "🇸🇮",
    "TR": "🇹🇷", "SG": "🇸🇬", "KR": "🇰🇷", "AU": "🇦🇺", "NZ": "🇳🇿", "BR": "🇧🇷",
    "MX": "🇲🇽", "IN": "🇮🇳", "ID": "🇮🇩", "TH": "🇹🇭", "VN": "🇻🇳", "PH": "🇵🇭",
    "RS": "🇷🇸", "MK": "🇲🇰", "AL": "🇦🇱", "BA": "🇧🇦", "ME": "🇲🇪", "IS": "🇮🇸",
    "BG": "🇧🇬", "HR": "🇭🇷",
}

SEED_VLESS_SOURCES = [
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
]
GITHUB_SEARCH_QUERIES = ["vless subscription", "free vless", "vless raw"]

HTTP_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://www.proxy-list.download/api/v1/get?type=http",
]
SOCKS5_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
]
TEST_URLS = ["https://api.ipify.org?format=json", "http://httpbin.org/ip"]
IP_PORT_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$")
_lock = asyncio.Lock()


def b64_decode_safe(s: str) -> str:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def validate_vless_link(link: str) -> str | None:
    """Проверка конфига VLESS перед добавлением в пул. Возвращает причину отсева или None.
    Главная причина ошибки клиента 'reality.publicKey: need 32 bytes':
    в исходных списках разделители бывают HTML-экранированы (&amp; вместо &),
    из-за чего клиент не видит pbk/sni. Такие ссылки сначала чинятся через
    html.unescape, а если pbk всё равно нет или он не 32 байта — узел выбрасывается.
    """
    try:
        parsed = urlparse(link)
        if parsed.scheme != "vless":
            return "not vless"
        uuid = parsed.username or ""
        if not UUID_RE.match(uuid):
            return "bad uuid"
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return "no host/port"
        from urllib.parse import parse_qs
        q = parse_qs(parsed.query)
        sec = (q.get("security", [""])[0] or "").lower()
        # Тип транспорта должен быть известным: в исходных списках бывает
        # мусор вида type=tcp#... — клиент такое не понимает
        # ('unsupported: network tcp#...') и узел не подключается.
        net = (q.get("type", ["tcp"])[0] or "tcp").lower()
        if net not in ("tcp", "raw", "ws", "grpc", "xhttp", "httpupgrade",
                       "splithttp", "kcp", "quic", "http"):
            return f"bad type: {net[:30]}"
        if sec not in ("", "reality", "tls", "none"):
            return f"bad security: {sec[:20]}"
        if sec == "reality":
            pbk = (q.get("pbk", [""])[0] or "").strip()
            if not pbk:
                return "reality without pbk"
            # pbk — base64url от 32-байтового ключа (43 символа без '=')
            if not re.fullmatch(r"[A-Za-z0-9_-]+", pbk):
                return "reality pbk bad chars"
            padded = pbk + "=" * (-len(pbk) % 4)
            try:
                raw = base64.urlsafe_b64decode(padded)
            except Exception:
                return "reality pbk not base64"
            if len(raw) != 32:
                return f"reality pbk {len(raw)} bytes, need 32"
            sni = (q.get("sni", [""])[0] or "").strip()
            if not sni:
                return "reality without sni"
        elif sec == "tls":
            sni = (q.get("sni", [""])[0] or "").strip()
            if not sni and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                return "tls without sni on IP host"
        return None
    except Exception as e:
        return f"parse error: {e}"


def parse_vpn_links(text: str) -> list[str]:
    """Только vless://. HTML-сущности (&amp; и т.п.) раскодируются до парсинга."""
    out: list[str] = []
    text = html.unescape(text.strip())
    if not text:
        return out
    if "://" not in text:
        decoded = b64_decode_safe(text)
        if decoded:
            text = html.unescape(decoded)
    for line in text.splitlines():
        line = html.unescape(line.strip())
        if not line:
            continue
        if line.startswith("vless://"):
            out.append(line)
        elif len(line) > 20 and "://" not in line:
            decoded = b64_decode_safe(line)
            if decoded.startswith("vless://"):
                out.append(html.unescape(decoded.strip()))
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def vless_priority(link: str) -> int:
    low = link.lower()
    if "reality" in low:
        return 2
    if "security=tls" in low or "tls" in low:
        return 1
    return 0


def parse_host_port(link: str):
    try:
        parsed = urlparse(link)
        if parsed.scheme != "vless":
            return None
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        query = parsed.query.lower()
        sni = host
        for part in parsed.query.split("&"):
            if part.lower().startswith("sni="):
                sni = part.split("=", 1)[1] or host
        use_tls = ("security=reality" in query or "security=tls" in query
                   or "tls" in query or port == 443)
        return (host, port, use_tls, sni)
    except Exception:
        return None


async def check_vpn_node(link: str):
    parsed = parse_host_port(link)
    if not parsed:
        return None
    host, port, use_tls, sni = parsed
    start = time.monotonic()
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
                timeout=3,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
        latency = (time.monotonic() - start) * 1000
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return latency
    except Exception:
        return None


def is_slow(latency, baseline):
    """Медленный узел для 5-минутного монитора. Узел считается медленным,
    только если задержка одновременно выше 2000 мс И в 3+ раза выше его
    обычной задержки. Раньше хватало одного условия — из-за этого монитор
    съедал узлы с высоким базовым пингом (например, Финляндию: база
    ~1500 мс, любой всплеск выше 2000 мс — и узел вылетал). Реальную
    скорость теперь решает замер 5 Мбит/с в полном цикле."""
    if latency is None:
        return False
    if not baseline or baseline <= 0:
        return latency > SLOW_MS
    return latency > SLOW_MS and latency > baseline * SLOW_RATIO


def parse_xray_node(link: str):
    """Параметры VLESS-ссылки для конфига Xray. None — тип транспорта не поддерживается."""
    try:
        from urllib.parse import parse_qs
        parsed = urlparse(link)
        if parsed.scheme != "vless":
            return None
        q = parse_qs(parsed.query)
        g = lambda k, d="": (q.get(k, [d])[0] or d)
        net = (g("type", "tcp") or "tcp").lower()
        # raw — это TCP в нотации VLESS-ссылок.
        if net == "raw":
            net = "tcp"
        if net not in ("tcp", "ws", "grpc", "xhttp", "httpupgrade"):
            return None
        return {
            "uuid": parsed.username, "host": parsed.hostname, "port": parsed.port,
            "security": (g("security") or "").lower(), "pbk": g("pbk"), "sni": g("sni"),
            "sid": g("sid"), "fp": g("fp", "chrome") or "chrome", "flow": g("flow"),
            "type": net, "path": g("path", "/") or "/", "host_hdr": g("host", ""),
            "service": g("serviceName", "") or "", "mode": g("mode", "auto") or "auto",
        }
    except Exception:
        return None


def xray_config_for(node: dict, port: int) -> dict:
    if node["security"] == "reality":
        stream = {"network": node["type"], "security": "reality",
                  "realitySettings": {"serverName": node["sni"], "publicKey": node["pbk"],
                                      "shortId": node["sid"], "fingerprint": node["fp"]}}
    elif node["security"] == "tls":
        stream = {"network": node["type"], "security": "tls",
                  "tlsSettings": {"serverName": node["sni"], "fingerprint": node["fp"]}}
    else:
        stream = {"network": node["type"], "security": "none"}
    if node["type"] == "ws":
        stream["wsSettings"] = {"path": node["path"],
                                "headers": {"Host": node["host_hdr"] or node["sni"] or node["host"]}}
    elif node["type"] == "grpc":
        stream["grpcSettings"] = {"serviceName": node["service"], "multiMode": False}
    elif node["type"] == "xhttp":
        stream["xhttpSettings"] = {"path": node["path"],
                                   "host": node["host_hdr"] or node["sni"] or node["host"],
                                   "mode": node["mode"]}
    elif node["type"] == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": node["path"],
                                         "host": node["host_hdr"] or node["sni"] or node["host"]}
    user = {"id": node["uuid"], "encryption": "none"}
    if node["flow"]:
        user["flow"] = node["flow"]
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "vless",
                           "settings": {"vnext": [{"address": node["host"], "port": node["port"],
                                                   "users": [user]}]},
                           "streamSettings": stream}]}


def _speed_test_sync(link: str, port: int):
    """Синхронный замер скорости одного узла: Xray + curl.
    Возвращает (Mbit/s, None) или (None, причина); причина 'skip' — тип
    транспорта не тестируется, узел не трогаем."""
    import subprocess
    node = parse_xray_node(link)
    if node is None:
        return None, "skip"
    # Xray не запускает VLESS без шифрования (security=none) на публичные IP —
    # это ограничение тестера, а не медленный узел, поэтому такие узлы
    # не трогаем: их судьбу решает монитор по handshake.
    if node["security"] == "none":
        return None, "skip"
    cfg_path = f"/tmp/xray-speed-{port}.json"
    try:
        with open(cfg_path, "w") as f:
            json.dump(xray_config_for(node, port), f)
    except Exception as e:
        return None, f"config write failed: {e}"
    proc = subprocess.Popen([XRAY_BIN, "-config", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        ok = False
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                s.close()
                ok = True
                break
            except OSError:
                time.sleep(0.2)
        if not ok:
            return None, "xray did not listen"
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}",
                            "--socks5-hostname", f"127.0.0.1:{port}",
                            "--max-time", str(SPEED_TEST_TIMEOUT), SPEED_TEST_URL],
                           capture_output=True, text=True, timeout=SPEED_TEST_TIMEOUT + 5)
        if r.returncode != 0:
            return None, f"curl rc={r.returncode}"
        try:
            bps = float(r.stdout.strip() or 0)
        except Exception:
            return None, "bad curl output"
        return bps * 8 / 1e6, None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        try:
            os.remove(cfg_path)
        except OSError:
            pass


async def speed_test_node(link: str, port: int):
    return await asyncio.to_thread(_speed_test_sync, link, port)


async def speed_test_many(links: list[str]) -> dict:
    """Замер скорости для списка ссылок (параллельно, до SPEED_CONCURRENCY).
    При неудаче или скорости ниже порога — одна повторная попытка,
    берётся лучший результат. Возвращает {link: (Mbit/s|None, причина|None)}."""
    sem = asyncio.Semaphore(SPEED_CONCURRENCY)
    results: dict = {}

    async def one(idx: int, link: str):
        async with sem:
            mbps, err = await speed_test_node(link, 19100 + idx)
            if err != "skip" and (mbps is None or mbps < SPEED_MIN_MBPS):
                mbps2, err2 = await speed_test_node(link, 19100 + idx)
                if mbps2 is not None and (mbps is None or mbps2 > mbps):
                    mbps, err = mbps2, err2
            results[link] = (mbps, err)

    await asyncio.gather(*[one(i, l) for i, l in enumerate(links)])
    return results


async def fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                log.warning("source %s -> HTTP %s", url, r.status)
                return ""
            return await r.text(errors="ignore")
    except Exception as e:
        log.warning("source %s failed: %s", url, e)
        return ""


def github_headers():
    h = {"Accept": "application/vnd.github+json", "User-Agent": "readall-service"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


async def github_api_get(session: aiohttp.ClientSession, url: str):
    try:
        async with session.get(url, headers=github_headers(),
                               timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                log.warning("github api %s -> %s", url, r.status)
                return None
            return await r.json()
    except Exception as e:
        log.warning("github api %s failed: %s", url, e)
        return None


async def discover_vless_sources(session: aiohttp.ClientSession) -> list[str]:
    found_urls: list[str] = []
    repos: list[str] = []
    for q in GITHUB_SEARCH_QUERIES:
        data = await github_api_get(
            session,
            f"https://api.github.com/search/repositories?q={quote(q)}&sort=updated&per_page=10",
        )
        if not data:
            continue
        for item in data.get("items", []) or []:
            name = item.get("full_name")
            if name and name not in repos:
                repos.append(name)
    log.info("github search found %d repos", len(repos))
    for repo in repos[:12]:
        contents = await github_api_get(
            session, f"https://api.github.com/repos/{repo}/contents/"
        )
        if not contents or not isinstance(contents, list):
            continue
        candidates = []
        for entry in contents:
            if entry.get("type") != "file":
                continue
            name = entry.get("name", "")
            if name.lower().endswith((".txt", ".sub")) or name.lower() in ("sub", "vless"):
                dl = entry.get("download_url")
                if dl:
                    candidates.append(dl)
        for path in ("sub", "sub.txt", "vless.txt", "vless"):
            candidates.append(f"https://raw.githubusercontent.com/{repo}/main/{path}")
            candidates.append(f"https://raw.githubusercontent.com/{repo}/master/{path}")
        for url in candidates:
            if url in found_urls or len(found_urls) >= 10:
                continue
            text = await fetch_text(session, url)
            if not text:
                continue
            links = parse_vpn_links(text)
            if len(links) >= 3:
                log.info("discovered vless source %s: %d vless", url, len(links))
                found_urls.append(url)
        if len(found_urls) >= 10:
            break
    return found_urls


def resolve_ip(host: str):
    """Синхронное DNS-резолвинг, вызывать в to_thread."""
    try:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return host
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip = info[4][0]
            if ":" not in ip:
                return ip
        return infos[0][4][0] if infos else None
    except Exception:
        return None


async def geo_lookup(session: aiohttp.ClientSession, ips: list[str], cache: dict) -> dict:
    """countryCode по IP через ip-api.com batch API, с кэшем. Возвращает {ip: cc}."""
    result = {}
    todo = []
    for ip in ips:
        if ip in cache:
            result[ip] = cache[ip]
        elif ip not in todo:
            todo.append(ip)
    # Batch API: до 100 IP за один запрос, лимит 15 запросов в минуту.
    # Одиночные запросы давали 429 уже на десятках IP, поэтому только batch.
    for i in range(0, len(todo), 100):
        batch = todo[i : i + 100]
        data = None
        for attempt in range(3):
            try:
                async with session.post(
                    "http://ip-api.com/batch",
                    json=[{"query": ip, "fields": "status,countryCode,query"} for ip in batch],
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as r:
                    if r.status == 429:
                        log.warning("ip-api batch 429, waiting 60s (attempt %d)", attempt + 1)
                        await asyncio.sleep(60)
                        continue
                    if r.status != 200:
                        log.warning("ip-api batch -> HTTP %s", r.status)
                        break
                    data = await r.json()
                    break
            except Exception as e:
                log.warning("ip-api batch failed: %s", e)
                await asyncio.sleep(5)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                ip = item.get("query")
                cc = item.get("countryCode") if item.get("status") == "success" else None
                if ip:
                    cache[ip] = cc
                    result[ip] = cc
        else:
            # fallback: одиночные запросы с длинной паузой
            for ip in batch:
                text = await fetch_text(session, f"http://ip-api.com/json/{ip}?fields=status,countryCode,query")
                try:
                    d = json.loads(text) if text else {}
                    cc = d.get("countryCode") if d.get("status") == "success" else None
                except Exception:
                    cc = None
                cache[ip] = cc
                result[ip] = cc
                await asyncio.sleep(1.5)
        if i + 100 < len(todo):
            await asyncio.sleep(4)
    return result


def flag_for(cc: str) -> str:
    """Флаг по коду страны через regional indicators, работает для любого ISO-кода."""
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())
    return FLAGS.get(cc, "🏳️")


def rename_vless(link: str, cc: str, num: int) -> str:
    flag = flag_for(cc)
    name = f"{flag} {cc} | Fast {num:02d}"
    base = link.split("#", 1)[0]
    return f"{base}#{name}"


def load_state():
    try:
        data = json.loads(STATE_FILE.read_text())
        if isinstance(data, dict):
            active = [x for x in data.get("active", []) if isinstance(x, str) and x.startswith("vless://")]
            data["active"] = active
            data.setdefault("fails", {})
            data.setdefault("slow", {})
            data.setdefault("baseline", {})
            data.setdefault("sources", {})
            data.setdefault("geo", {})
            data.setdefault("reserve", [])
            data.setdefault("monitor", {})
            data.setdefault("rare_date", "")
            data.setdefault("rare_countries", [])
            return data
    except Exception:
        pass
    return {"active": [], "fails": {}, "slow": {}, "baseline": {}, "sources": {}, "geo": {}, "reserve": [], "monitor": {}, "rare_date": "", "rare_countries": []}


def save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    except Exception as e:
        log.warning("cannot save state: %s", e)


async def collect_vpn(session: aiohttp.ClientSession):
    """Полный цикл: поиск, проверка, Geo, blacklist, порядок стран."""
    state = load_state()
    fails: dict[str, int] = dict(state.get("fails", {}))
    slow: dict[str, int] = dict(state.get("slow", {}))
    baseline: dict[str, float] = dict(state.get("baseline", {}))
    geo_cache: dict = dict(state.get("geo", {}))
    source_state: dict[str, dict] = dict(state.get("sources", {}))

    discovered = await discover_vless_sources(session)
    all_sources = list(SEED_VLESS_SOURCES)
    for u in discovered:
        if u not in all_sources:
            all_sources.append(u)
    log.info("vpn sources (seed+discovered): %d", len(all_sources))

    candidates: list[str] = []
    live_sources: list[str] = []
    for url in all_sources:
        text = await fetch_text(session, url)
        if not text:
            source_state[url] = {"fails": source_state.get(url, {}).get("fails", 0) + 1}
            continue
        found = parse_vpn_links(text)
        if not found:
            log.info("vpn source %s: 0 vless, dropped", url)
            source_state[url] = {"fails": source_state.get(url, {}).get("fails", 0) + 1}
            continue
        source_state[url] = {"fails": 0}
        live_sources.append(url)
        log.info("vpn source %s: %d vless", url, len(found))
        candidates.extend(found)
    source_state = {k: v for k, v in source_state.items() if v.get("fails", 0) < 2}
    seen, uniq = set(), []
    for x in candidates:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    candidates = uniq
    # Валидация конфигов: Reality без pbk/sni или с pbk не 32 байта —
    # это именно та ошибка 'reality.publicKey: need 32 bytes' из клиента.
    # Такие узлы выбрасываются до проверки, а не попадают в подписку.
    from collections import Counter as _Counter
    invalid_reasons: _Counter = _Counter()
    valid_candidates: list[str] = []
    for x in candidates:
        reason = validate_vless_link(x)
        if reason:
            invalid_reasons[reason] += 1
        else:
            valid_candidates.append(x)
    if invalid_reasons:
        log.info("vpn config validation dropped %d: %s", sum(invalid_reasons.values()), dict(invalid_reasons))
    candidates = valid_candidates
    # Перемешиваем с фиксированным seed: иначе первые 600 кандидатов
    # почти все из одних и тех же стран (DE/NL/US), а FI/PL/SE почти не попадают.
    random.Random(42).shuffle(candidates)
    log.info("vpn candidates total (vless only, valid): %d from %d live sources", len(candidates), len(live_sources))

    async def check_links(links: list[str]) -> list[tuple[int, float, str]]:
        out: list[tuple[int, float, str]] = []
        for i in range(0, len(links), 50):
            batch = links[i : i + 50]
            results = await asyncio.gather(*[check_vpn_node(x) for x in batch])
            for link, lat in zip(batch, results):
                if lat is not None:
                    out.append((vless_priority(link), lat, link))
                    baseline[link] = lat
            await asyncio.sleep(0.2)
        return out

    async def group_by_country(checked_list):
        hosts = []
        for _, _, link in checked_list:
            parsed = parse_host_port(link)
            if parsed:
                hosts.append(parsed[0])
        unique_hosts = list(dict.fromkeys(hosts))
        ip_by_host: dict[str, str] = {}
        for host in unique_hosts:
            ip = await asyncio.to_thread(resolve_ip, host)
            if ip:
                ip_by_host[host] = ip
        ips = list(dict.fromkeys(ip_by_host.values()))
        geo_by_ip = await geo_lookup(session, ips, geo_cache)
        grouped: dict[str, list[tuple[int, float, str]]] = {}
        dropped = 0
        for prio, lat, link in checked_list:
            parsed = parse_host_port(link)
            if not parsed:
                continue
            ip = ip_by_host.get(parsed[0])
            cc = geo_by_ip.get(ip) if ip else None
            if not cc:
                continue
            if cc in BLACKLIST:
                dropped += 1
                continue
            grouped.setdefault(cc, []).append((prio, lat, link))
        return grouped, dropped

    checked = await check_links(candidates[:2000])
    log.info("vpn checked ok: %d", len(checked))
    by_country, dropped_blacklist = await group_by_country(checked)
    log.info("geo blacklist dropped: %d nodes", dropped_blacklist)
    # Ровно 6 на страну: если после первого прохода какая-то основная
    # страна не набрала 6, проверяем остальных кандидатов, пока не наберём
    # или пока кандидаты не кончатся.
    next_idx = 2000
    while next_idx < len(candidates) and any(
        len(by_country.get(cc, [])) < PER_COUNTRY for cc in MAIN_COUNTRIES
    ):
        extra = candidates[next_idx : next_idx + 500]
        next_idx += len(extra)
        log.info("country short, extra check pass: %d more candidates", len(extra))
        checked2 = await check_links(extra)
        log.info("vpn checked ok (extra pass): %d", len(checked2))
        grouped2, dropped2 = await group_by_country(checked2)
        dropped_blacklist += dropped2
        for cc, grp in grouped2.items():
            by_country.setdefault(cc, []).extend(grp)
    # Фолбэк: если страна всё ещё не набрала 6 — добираем из прошлого пула
    # (узлы, которые уже работали; монитор выкинет их, если они умерли).
    prev_active = state.get("active", [])
    for cc in MAIN_COUNTRIES:
        if len(by_country.get(cc, [])) < PER_COUNTRY:
            need = PER_COUNTRY - len(by_country.get(cc, []))
            have = {t[2] for t in by_country.get(cc, [])}
            prev_links = []
            for old in prev_active:
                occ, _ = parse_slot(old)
                if occ != cc:
                    continue
                base = old.split("#", 1)[0]
                if base in have or base in prev_links:
                    continue
                if validate_vless_link(base):
                    continue
                prev_links.append(base)
            prev_links = prev_links[:need]
            if prev_links:
                log.info("country %s: fallback from previous pool: %d nodes", cc, len(prev_links))
                checked3 = await check_links(prev_links)
                grouped3, _ = await group_by_country(checked3)
                for c2, grp in grouped3.items():
                    by_country.setdefault(c2, []).extend(grp)
    for cc in by_country:
        by_country[cc].sort(key=lambda t: (-t[0], t[1]))

    final: list[str] = []
    used_links: set[str] = set()
    renamed_baseline: dict[str, float] = {}
    layout: dict[str, int] = {}
    for cc in MAIN_COUNTRIES:
        group = [t for t in by_country.get(cc, []) if t[2] not in used_links]
        take = group[:PER_COUNTRY]
        for idx, (prio, lat, link) in enumerate(take, start=1):
            renamed = rename_vless(link, cc, idx)
            final.append(renamed)
            renamed_baseline[renamed] = lat
            used_links.add(link)
        layout[cc] = len(take)
        if len(take) < PER_COUNTRY:
            log.warning("country %s: only %d nodes (need %d)", cc, len(take), PER_COUNTRY)
    # Редкие страны — случайные, меняются ровно раз в сутки.
    # Seed = дата UTC: в течение дня набор стабилен, на следующий день — новый.
    today = time.strftime("%Y-%m-%d", time.gmtime())
    saved_rare_date = state.get("rare_date")
    saved_rare = [c for c in state.get("rare_countries", []) if c in by_country]
    rare_pool = [cc for cc in sorted(by_country.keys())
                 if cc not in MAIN_COUNTRIES and cc not in BLACKLIST]
    if saved_rare_date == today and len(saved_rare) >= RARE_COUNT:
        rare_picked = saved_rare[:RARE_COUNT]
        log.info("rare countries kept for %s: %s", today, rare_picked)
    else:
        rng = random.Random(f"rare-{today}")
        rng.shuffle(rare_pool)
        rare_picked = rare_pool[:RARE_COUNT]
        log.info("rare countries rotated for %s: %s", today, rare_picked)
    for cc in rare_picked:
        if cc not in by_country:
            continue
        prio, lat, link = by_country[cc][0]
        renamed = rename_vless(link, cc, 1)
        final.append(renamed)
        renamed_baseline[renamed] = lat
        used_links.add(link)
    layout["rare_date"] = today
    # Speed gate: реальный замер скорости каждого узла пула через Xray.
    # Порог 5 Мбит/с: медленнее — узел улетает и заменяется из резерва
    # той же страны (для редкой — из новой случайной страны).
    reserve_by_country: dict[str, list[tuple[int, float, str]]] = {}
    for cc, group in by_country.items():
        rest = [t for t in group if t[2] not in used_links]
        if rest:
            reserve_by_country[cc] = sorted(rest, key=lambda t: (-t[0], t[1]))
    speed_results = await speed_test_many([l.split("#", 1)[0] for l in final])
    gated_final: list[str] = []
    dropped_speed: list[tuple[str, float | None, str | None]] = []
    replaced_speed = 0
    for renamed in final:
        base = renamed.split("#", 1)[0]
        cc, num = parse_slot(renamed)
        mbps, err = speed_results.get(base, (None, "no result"))
        if err == "skip":
            log.info("speed gate skip (untestable type): %s", renamed[:60])
            gated_final.append(renamed)
            continue
        if mbps is not None and mbps >= SPEED_MIN_MBPS:
            gated_final.append(renamed)
            continue
        dropped_speed.append((renamed, mbps, err))
        replacement = None
        if cc in MAIN_COUNTRIES:
            cands = reserve_by_country.get(cc, [])
            for attempt in range(3):
                if not cands:
                    break
                _, _, cand = cands.pop(0)
                mb2, err2 = await speed_test_node(cand, 19200 + replaced_speed * 7 + attempt)
                if err2 == "skip":
                    continue
                if mb2 is not None and mb2 >= SPEED_MIN_MBPS:
                    replacement = rename_vless(cand, cc, num)
                    renamed_baseline[replacement] = baseline.get(cand, 0)
                    used_links.add(cand)
                    break
        else:
            avail = [c for c in reserve_by_country.keys()
                     if c not in MAIN_COUNTRIES and c not in rare_picked]
            random.Random().shuffle(avail)
            for new_cc in avail:
                cands = reserve_by_country.get(new_cc, [])
                for attempt in range(3):
                    if not cands:
                        break
                    _, _, cand = cands.pop(0)
                    mb2, err2 = await speed_test_node(cand, 19200 + replaced_speed * 7 + attempt)
                    if err2 == "skip":
                        continue
                    if mb2 is not None and mb2 >= SPEED_MIN_MBPS:
                        replacement = rename_vless(cand, new_cc, 1)
                        renamed_baseline[replacement] = baseline.get(cand, 0)
                        used_links.add(cand)
                        rare_picked = [new_cc if c == cc else c for c in rare_picked]
                        break
                if replacement:
                    break
        if replacement:
            gated_final.append(replacement)
            replaced_speed += 1
        else:
            log.warning("speed gate: no replacement for %s", renamed[:60])
    final = gated_final
    log.info("speed gate: tested %d, dropped %d, replaced %d",
             len(speed_results), len(dropped_speed), replaced_speed)
    for r, mbps, err in dropped_speed:
        log.info("speed gate dropped: %s speed=%s err=%s",
                 r[:60], f"{mbps:.2f} Mbit/s" if mbps else None, err)
    layout["rare"] = rare_picked
    log.info("vpn layout: %s rare=%s", layout, rare_picked)

    reserve: list[str] = []
    for cc, group in by_country.items():
        for prio, lat, link in group:
            if link not in used_links:
                reserve.append(link)
    reserve.sort(key=lambda x: (-vless_priority(x), baseline.get(x, 9999)))
    reserve = reserve[:200]

    save_state({
        "active": final,
        "fails": {},
        "slow": {},
        "baseline": renamed_baseline,
        "sources": source_state,
        "geo": geo_cache,
        "reserve": reserve,
        "monitor": {},
        "layout": layout,
        "rare_date": today,
        "rare_countries": rare_picked,
    })
    log.info("vpn final pool: %d vless, layout=%s", len(final), layout)
    return final, layout


def parse_proxies(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = IP_PORT_RE.match(line)
        if m:
            port = int(m.group(2))
            if 1 <= port <= 65535:
                out.append(f"{m.group(1)}:{port}")
            continue
        found = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})", line)
        for ip, port in found:
            p = int(port)
            if 1 <= p <= 65535:
                out.append(f"{ip}:{p}")
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


async def check_http_proxy(session: aiohttp.ClientSession, proxy: str):
    proxy_url = f"http://{proxy}"
    for url in TEST_URLS:
        start = time.monotonic()
        try:
            async with session.get(
                url, proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=5)
            ) as r:
                if r.status == 200:
                    await r.read()
                    return (time.monotonic() - start) * 1000
        except Exception:
            continue
    return None


async def check_socks5_proxy(proxy: str):
    try:
        ip, port_s = proxy.split(":")
        port = int(port_s)
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=5
        )
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            if resp != b"\x05\x00":
                return None
            writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
            await writer.drain()
            resp2 = await asyncio.wait_for(reader.readexactly(10), timeout=5)
            if len(resp2) >= 2 and resp2[1] == 0x00:
                return (time.monotonic() - start) * 1000
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return None


async def collect_proxies(session: aiohttp.ClientSession, geo_cache: dict):
    http_candidates: list[str] = []
    socks_candidates: list[str] = []
    for url in HTTP_PROXY_SOURCES:
        text = await fetch_text(session, url)
        if text:
            found = parse_proxies(text)
            log.info("http proxy source %s: %d", url, len(found))
            http_candidates.extend(found)
    for url in SOCKS5_PROXY_SOURCES:
        text = await fetch_text(session, url)
        if text:
            found = parse_proxies(text)
            log.info("socks5 proxy source %s: %d", url, len(found))
            socks_candidates.extend(found)

    def dedup(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    http_candidates = dedup(http_candidates)[:800]
    socks_candidates = dedup(socks_candidates)[:800]
    log.info("proxy candidates: http=%d socks5=%d", len(http_candidates), len(socks_candidates))

    async def check_and_sort(candidates, checker, name):
        scored: list[tuple[float, str]] = []
        for i in range(0, len(candidates), 50):
            batch = candidates[i : i + 50]
            results = await asyncio.gather(*[checker(p) for p in batch])
            for p, lat in zip(batch, results):
                if lat is not None:
                    scored.append((lat, p))
            if len(scored) >= MAX_PROXY:
                break
            await asyncio.sleep(0.1)
        ips = [p.split(":")[0] for _, p in scored]
        geo_by_ip = await geo_lookup(session, list(dict.fromkeys(ips)), geo_cache)
        filtered: list[tuple[float, str]] = []
        dropped = 0
        for lat, p in scored:
            cc = geo_by_ip.get(p.split(":")[0])
            if cc in BLACKLIST:
                dropped += 1
                continue
            filtered.append((lat, p))
        filtered.sort(key=lambda t: t[0])
        log.info("%s: ok=%d, blacklist dropped=%d", name, len(filtered), dropped)
        return [p for _, p in filtered[:MAX_PROXY]]

    good_http = await check_and_sort(
        http_candidates,
        lambda p: check_http_proxy(session, p),
        "http",
    )
    good_socks = await check_and_sort(
        socks_candidates,
        check_socks5_proxy,
        "socks5",
    )
    log.info("proxies ok: http=%d socks5=%d", len(good_http), len(good_socks))
    return good_http, good_socks, geo_cache


async def github_put_file(session: aiohttp.ClientSession, path: str, content: bytes, message: str):
    if not GITHUB_TOKEN:
        return False
    owner, repo = GITHUB_REPO.split("/", 1)
    base = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "readall-service",
    }
    sha = None
    try:
        async with session.get(
            base, headers=headers, params={"ref": GITHUB_BRANCH},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as r:
            if r.status == 200:
                data = await r.json()
                sha = data.get("sha")
    except Exception as e:
        log.warning("github get %s failed: %s", path, e)
    payload = {
        "message": message,
        "content": base64.b64encode(content).decode(),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha
    try:
        async with session.put(
            base, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=20)
        ) as r:
            if r.status in (200, 201):
                log.info("github published %s", path)
                return True
            body = await r.text()
            log.warning("github put %s -> %s %s", path, r.status, body[:200])
            return False
    except Exception as e:
        log.warning("github put %s failed: %s", path, e)
        return False


async def publish_all(session: aiohttp.ClientSession):
    if not GITHUB_TOKEN:
        log.info("GITHUB_TOKEN not set, skipping GitHub publish")
        return
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    sub = (OUTPUT_DIR / "subscription.txt").read_bytes()
    await github_put_file(session, "subscription.txt", sub, f"Update subscription {ts}")
    await github_put_file(session, "http_proxies.txt", (OUTPUT_DIR / "http_proxies.txt").read_bytes(), f"Update http proxies {ts}")
    await github_put_file(session, "socks5_proxies.txt", (OUTPUT_DIR / "socks5_proxies.txt").read_bytes(), f"Update socks5 proxies {ts}")


def write_subscription(vpn: list[str]):
    sub_b64 = base64.b64encode("\n".join(vpn).encode()).decode()
    (OUTPUT_DIR / "subscription.txt").write_text(sub_b64)
    (OUTPUT_DIR / "subscription_raw.txt").write_text("\n".join(vpn) + "\n" if vpn else "")
    log.info("wrote subscription.txt: %d vless nodes, %d bytes b64", len(vpn), len(sub_b64))


async def run_cycle():
    async with _lock:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        async with aiohttp.ClientSession() as session:
            vpn, layout = await collect_vpn(session)
            write_subscription(vpn)
            state = load_state()
            geo_cache = dict(state.get("geo", {}))
            http_p, socks_p, geo_cache = await collect_proxies(session, geo_cache)
            (OUTPUT_DIR / "http_proxies.txt").write_text("\n".join(http_p) + "\n" if http_p else "")
            (OUTPUT_DIR / "socks5_proxies.txt").write_text("\n".join(socks_p) + "\n" if socks_p else "")
            log.info("wrote http_proxies.txt=%d socks5_proxies.txt=%d", len(http_p), len(socks_p))
            state = load_state()
            state["geo"] = geo_cache
            save_state(state)
            await publish_all(session)
            return {"vpn": len(vpn), "http": len(http_p), "socks5": len(socks_p), "layout": layout}


SLOT_RE = re.compile(r"([A-Z]{2}) \| Fast (\d+)")


def parse_slot(link: str) -> tuple[str, int]:
    """Страна и номер слота из имени узла, например '🇩🇪 DE | Fast 01' -> ('DE', 1)."""
    frag = link.split("#", 1)[1] if "#" in link else ""
    m = SLOT_RE.search(frag)
    if m:
        return m.group(1), int(m.group(2))
    return "", 0


async def country_of_link(session: aiohttp.ClientSession, link: str, geo_cache: dict) -> str | None:
    """Страна резервного узла по его хосту (DNS + geo-кэш / ip-api)."""
    parsed = parse_host_port(link)
    if not parsed:
        return None
    ip = await asyncio.to_thread(resolve_ip, parsed[0])
    if not ip:
        return None
    if ip in geo_cache:
        return geo_cache[ip]
    geo = await geo_lookup(session, [ip], geo_cache)
    return geo.get(ip)


async def monitor_loop():
    """5-минутный мониторинг активного пула. Замена только после 2 неудач/медленных проверок."""
    log.info("monitor started, interval=%ss, slow_ms=%s", MONITOR_INTERVAL, SLOW_MS)
    await asyncio.sleep(60)
    while True:
        try:
            await asyncio.sleep(MONITOR_INTERVAL)
            async with _lock:
                state = load_state()
                active = list(state.get("active", []))
                if not active:
                    continue
                fails = dict(state.get("fails", {}))
                slow = dict(state.get("slow", {}))
                baseline = dict(state.get("baseline", {}))
                reserve = list(state.get("reserve", []))
                results = await asyncio.gather(*[check_vpn_node(x) for x in active])
                changed = False
                # Слоты в исходном порядке: ('keep', link) или ('drop', cc, num).
                # Замены вставляются на место выпавших слотов, порядок списка не ломается.
                slots: list[tuple] = []
                for link, lat in zip(active, results):
                    base = baseline.get(link, 0)
                    if lat is None:
                        fails[link] = fails.get(link, 0) + 1
                        slow[link] = 0
                        if fails[link] >= 2:
                            log.info("monitor drop after 2 fails: %s", link[:60])
                            fails.pop(link, None)
                            slots.append(("drop",) + parse_slot(link))
                            changed = True
                            continue
                        slots.append(("keep", link))
                    elif is_slow(lat, base):
                        slow[link] = slow.get(link, 0) + 1
                        fails[link] = 0
                        if slow[link] >= 2:
                            log.info("monitor drop after 2 slow (%.0fms, base %.0fms): %s", lat, base, link[:60])
                            slow.pop(link, None)
                            slots.append(("drop",) + parse_slot(link))
                            changed = True
                            continue
                        slots.append(("keep", link))
                    else:
                        fails[link] = 0
                        slow[link] = 0
                        baseline[link] = lat
                        slots.append(("keep", link))
                new_active: list[str] = [s[1] for s in slots if s[0] == "keep"]
                if changed and reserve:
                    # Замена с сохранением слота: для основной страны — узел той же
                    # страны, для редкой — узел из новой случайной страны
                    # (не из текущего набора редких), чтобы набор редких обновился сразу.
                    geo_cache = dict(state.get("geo", {}))
                    rare_now = list(state.get("rare_countries", []))
                    replacements: dict[int, str] = {}
                    added = 0
                    async with aiohttp.ClientSession() as _sess:
                        for idx, slot in enumerate(slots):
                            if slot[0] != "drop":
                                continue
                            _, slot_cc, slot_num = slot
                            is_rare_slot = slot_cc not in MAIN_COUNTRIES
                            for cand in list(reserve):
                                cand_cc = await country_of_link(_sess, cand, geo_cache)
                                if is_rare_slot:
                                    if cand_cc is None or cand_cc in MAIN_COUNTRIES or cand_cc in rare_now:
                                        continue
                                    new_cc = cand_cc
                                    new_num = 1
                                else:
                                    if cand_cc != slot_cc:
                                        continue
                                    new_cc, new_num = slot_cc, slot_num
                                lat = await check_vpn_node(cand)
                                if lat is None or is_slow(lat, 0):
                                    continue
                                renamed = rename_vless(cand, new_cc, new_num)
                                replacements[idx] = renamed
                                reserve.remove(cand)
                                baseline[renamed] = lat
                                added += 1
                                if is_rare_slot:
                                    rare_now = [c for c in rare_now if c != slot_cc] + [new_cc]
                                    log.info("monitor rare rotated: %s -> %s", slot_cc, new_cc)
                                break
                    state["rare_countries"] = rare_now
                    state["geo"] = geo_cache
                    log.info("monitor replaced %d nodes from reserve", added)
                    # Собираем список заново в исходном порядке слотов.
                    new_active = []
                    for idx, slot in enumerate(slots):
                        if slot[0] == "keep":
                            new_active.append(slot[1])
                        elif idx in replacements:
                            new_active.append(replacements[idx])
                    state["active"] = new_active
                    state["fails"] = {k: v for k, v in fails.items() if k in new_active}
                    state["slow"] = {k: v for k, v in slow.items() if k in new_active}
                    state["baseline"] = {k: baseline.get(k, 0) for k in new_active}
                    state["reserve"] = reserve
                    save_state(state)
                    write_subscription(new_active)
                    async with aiohttp.ClientSession() as session:
                        await publish_all(session)
                elif changed:
                    state["active"] = new_active
                    save_state(state)
                    write_subscription(new_active)
                else:
                    state["fails"] = fails
                    state["slow"] = slow
                    state["baseline"] = baseline
                    save_state(state)
        except Exception as e:
            log.exception("monitor failed: %s", e)


async def speed_check_current():
    """Разовая проверка текущего пула (--speed-check): реальный замер
    скорости каждого узла, замена медленных (<5 Мбит/с) из резерва, публикация."""
    state = load_state()
    active = list(state.get("active", []))
    reserve = list(state.get("reserve", []))
    if not active:
        log.info("speed-check: pool is empty")
        return
    geo_cache = dict(state.get("geo", {}))
    rare_now = list(state.get("rare_countries", []))
    baseline = dict(state.get("baseline", {}))
    results = await speed_test_many([l.split("#", 1)[0] for l in active])
    slots: list[tuple] = []
    dropped = 0
    for link in active:
        base = link.split("#", 1)[0]
        mbps, err = results.get(base, (None, "no result"))
        if err == "skip":
            log.info("speed-check skip (untestable type): %s", link[:60])
            slots.append(("keep", link))
        elif mbps is not None and mbps >= SPEED_MIN_MBPS:
            log.info("speed-check ok: %s %.2f Mbit/s", link[:60], mbps)
            slots.append(("keep", link))
        else:
            log.info("speed-check drop: %s speed=%s err=%s", link[:60],
                     f"{mbps:.2f}" if mbps else None, err)
            slots.append(("drop",) + parse_slot(link))
            dropped += 1
    replacements: dict[int, str] = {}
    replaced = 0
    if dropped and reserve:
        async with aiohttp.ClientSession() as _sess:
            for idx, slot in enumerate(slots):
                if slot[0] != "drop":
                    continue
                _, slot_cc, slot_num = slot
                is_rare_slot = slot_cc not in MAIN_COUNTRIES
                for cand in list(reserve):
                    cand_cc = await country_of_link(_sess, cand, geo_cache)
                    if is_rare_slot:
                        if cand_cc is None or cand_cc in MAIN_COUNTRIES or cand_cc in rare_now:
                            continue
                        new_cc, new_num = cand_cc, 1
                    else:
                        if cand_cc != slot_cc:
                            continue
                        new_cc, new_num = slot_cc, slot_num
                    mb2, err2 = await speed_test_node(cand, 19300 + idx)
                    if err2 == "skip":
                        continue
                    if mb2 is None or mb2 < SPEED_MIN_MBPS:
                        continue
                    renamed = rename_vless(cand, new_cc, new_num)
                    replacements[idx] = renamed
                    reserve.remove(cand)
                    baseline[renamed] = 0
                    replaced += 1
                    if is_rare_slot:
                        rare_now = [c for c in rare_now if c != slot_cc] + [new_cc]
                        log.info("speed-check rare rotated: %s -> %s", slot_cc, new_cc)
                    break
    new_active: list[str] = []
    for idx, slot in enumerate(slots):
        if slot[0] == "keep":
            new_active.append(slot[1])
        elif idx in replacements:
            new_active.append(replacements[idx])
    state["active"] = new_active
    state["reserve"] = reserve
    state["rare_countries"] = rare_now
    state["geo"] = geo_cache
    state["baseline"] = {k: baseline.get(k, 0) for k in new_active}
    state["fails"] = {}
    state["slow"] = {}
    save_state(state)
    write_subscription(new_active)
    async with aiohttp.ClientSession() as session:
        await publish_all(session)
    log.info("speed-check done: tested %d, dropped %d, replaced %d, pool %d",
             len(active), dropped, replaced, len(new_active))


async def main_loop():
    log.info("readall service started, interval=%ss, monitor=%ss, output=%s", INTERVAL, MONITOR_INTERVAL, OUTPUT_DIR)
    await asyncio.gather(run_cycle_loop(), monitor_loop())


async def run_cycle_loop():
    while True:
        try:
            result = await run_cycle()
            log.info("cycle done: %s", result)
        except Exception as e:
            log.exception("cycle failed: %s", e)
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    if "--speed-check" in sys.argv:
        asyncio.run(speed_check_current())
    elif "--once" in sys.argv:
        asyncio.run(run_cycle())
    else:
        asyncio.run(main_loop())
