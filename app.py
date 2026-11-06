#!/usr/bin/env python3
"""readall — автономный сервис сбора, валидации и публикации сетевых конфигураций.

Модуль 1: VPN для приложения (VLESS / VMess / Shadowsocks)
  - сбор из открытых raw-списков на GitHub (без Telegram)
  - проверка TCP + TLS handshake, таймаут 3 с, замер задержки
  - Sticky Pool: узел выбывает только после 2 неудач подряд
  - экспорт base64-подписки для Hiddify / Nekobox

Модуль 2: Прокси для скриптов (HTTP / SOCKS5)
  - парсинг открытых прокси без авторизации
  - проверка реальными запросами
  - http_proxies.txt / socks5_proxies.txt, по одному ip:port на строку

Публикация: файлы в OUTPUT_DIR, при наличии GITHUB_TOKEN — коммиты
в foto-co-zvezdoy/readall через GitHub Contents API.
"""
import asyncio
import base64
import json
import logging
import os
import re
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

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
MAX_VPN = int(os.environ.get("MAX_VPN_NODES", "100"))
MAX_PROXY = int(os.environ.get("MAX_PROXIES", "200"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "foto-co-zvezdoy/readall")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")

VPN_SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mix",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/subscriptions/mixed",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
]

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


def b64_decode_safe(s: str) -> str:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_vpn_links(text: str) -> list[str]:
    out: list[str] = []
    text = text.strip()
    if not text:
        return out
    # whole file may be base64 subscription
    if "://" not in text:
        decoded = b64_decode_safe(text)
        if decoded:
            text = decoded
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # line itself may be base64-encoded vmess/vless
        if line.startswith(("vless://", "vmess://", "ss://", "trojan://")):
            out.append(line)
        elif len(line) > 20 and "://" not in line:
            decoded = b64_decode_safe(line)
            if decoded.startswith(("vless://", "vmess://", "ss://")):
                out.append(decoded.strip())
    # dedup, preserve order
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def parse_host_port(link: str):
    """Return (host, port, use_tls) or None."""
    try:
        if link.startswith("vmess://"):
            payload = b64_decode_safe(link[8:])
            data = json.loads(payload)
            host = data.get("add") or data.get("address")
            port = int(data.get("port") or 0)
            tls = str(data.get("tls", "")).lower() in ("tls", "true", "1")
            return (host, port, tls) if host and port else None
        if link.startswith("ss://"):
            rest = link[5:]
            # ss://base64(method:pass@host:port)#name  or ss://base64@host:port
            if "@" in rest:
                after = rest.split("@", 1)[1]
                hostport = after.split("#")[0].split("/")[0].split("?")[0]
                if ":" in hostport:
                    host, port = hostport.rsplit(":", 1)
                    return (host, int(port), int(port) == 443)
            else:
                decoded = b64_decode_safe(rest.split("#")[0].split("/")[0])
                if "@" in decoded:
                    hostport = decoded.split("@", 1)[1].strip()
                    if ":" in hostport:
                        host, port = hostport.rsplit(":", 1)
                        return (host, int(port), int(port) == 443)
            return None
        # vless://, trojan://, etc: scheme://uuid@host:port?params#name
        parsed = urlparse(link)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        query = parsed.query.lower()
        tls = "tls" in query or "security=tls" in query or port == 443
        return (host, port, tls)
    except Exception:
        return None


async def check_vpn_node(link: str):
    """TCP connect + TLS handshake if needed, timeout 3 s. Return latency ms or None."""
    parsed = parse_host_port(link)
    if not parsed:
        return None
    host, port, use_tls = parsed
    start = time.monotonic()
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
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


def load_state():
    try:
        data = json.loads(STATE_FILE.read_text())
        if isinstance(data, dict) and isinstance(data.get("active"), list):
            return data
    except Exception:
        pass
    return {"active": [], "fails": {}}


def save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    except Exception as e:
        log.warning("cannot save state: %s", e)


async def collect_vpn(session: aiohttp.ClientSession):
    """Sticky Pool: active nodes are checked first, removed only after 2 consecutive failures."""
    state = load_state()
    active: list[str] = list(state.get("active", []))
    fails: dict[str, int] = dict(state.get("fails", {}))

    # 1) fetch candidates
    candidates: list[str] = []
    for url in VPN_SOURCES:
        text = await fetch_text(session, url)
        if text:
            found = parse_vpn_links(text)
            log.info("vpn source %s: %d links", url, len(found))
            candidates.extend(found)
    # dedup candidates, preserve order
    seen, uniq = set(), []
    for x in candidates:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    candidates = uniq
    log.info("vpn candidates total: %d", len(candidates))

    # 2) check active pool first (sticky)
    kept: list[tuple[float, str]] = []
    if active:
        results = await asyncio.gather(*[check_vpn_node(x) for x in active])
        for link, lat in zip(active, results):
            if lat is not None:
                fails[link] = 0
                kept.append((lat, link))
            else:
                fails[link] = fails.get(link, 0) + 1
                if fails[link] < 2:
                    # keep for one more chance, but mark as slow (put at end)
                    log.info("vpn sticky keep (fail %d/2): %s", fails[link], link[:60])
                    kept.append((9999.0, link))
                else:
                    log.info("vpn drop after 2 fails: %s", link[:60])
                    fails.pop(link, None)
        log.info("vpn sticky kept: %d / %d", len(kept), len(active))

    # 3) fill pool with fresh candidates that pass
    kept_links = {x for _, x in kept}
    need = MAX_VPN - len(kept)
    if need > 0:
        fresh = [x for x in candidates if x not in kept_links][:400]
        # check in batches to avoid too many concurrent connections
        for i in range(0, len(fresh), 50):
            batch = fresh[i : i + 50]
            results = await asyncio.gather(*[check_vpn_node(x) for x in batch])
            for link, lat in zip(batch, results):
                if lat is not None and len(kept) < MAX_VPN:
                    kept.append((lat, link))
                    fails[link] = 0
            if len(kept) >= MAX_VPN:
                break
            await asyncio.sleep(0.2)

    kept.sort(key=lambda t: t[0])
    final = [x for _, x in kept[:MAX_VPN]]
    save_state({"active": final, "fails": {k: v for k, v in fails.items() if k in final}})
    log.info("vpn final pool: %d nodes", len(final))
    return final


def parse_proxies(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # handle "ip:port" or "ip,port" or JSON-ish
        m = IP_PORT_RE.match(line)
        if m:
            port = int(m.group(2))
            if 1 <= port <= 65535:
                out.append(f"{m.group(1)}:{port}")
            continue
        # try to find ip:port inside line
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


async def check_http_proxy(session: aiohttp.ClientSession, proxy: str) -> bool:
    proxy_url = f"http://{proxy}"
    for url in TEST_URLS:
        try:
            async with session.get(
                url, proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=5)
            ) as r:
                if r.status == 200:
                    await r.read()
                    return True
        except Exception:
            continue
    return False


async def check_socks5_proxy(proxy: str) -> bool:
    """Raw SOCKS5 handshake + CONNECT to 1.1.1.1:80, timeout 5 s."""
    try:
        ip, port_s = proxy.split(":")
        port = int(port_s)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=5
        )
        try:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            if resp != b"\x05\x00":
                return False
            # CONNECT 1.1.1.1:80
            writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x00\x50")
            await writer.drain()
            resp2 = await asyncio.wait_for(reader.readexactly(10), timeout=5)
            return len(resp2) >= 2 and resp2[1] == 0x00
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return False


async def collect_proxies(session: aiohttp.ClientSession):
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

    # dedup
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

    # check http in batches
    good_http: list[str] = []
    for i in range(0, len(http_candidates), 50):
        batch = http_candidates[i : i + 50]
        results = await asyncio.gather(*[check_http_proxy(session, p) for p in batch])
        good_http.extend([p for p, ok in zip(batch, results) if ok])
        if len(good_http) >= MAX_PROXY:
            break
        await asyncio.sleep(0.1)
    good_http = good_http[:MAX_PROXY]

    good_socks: list[str] = []
    for i in range(0, len(socks_candidates), 50):
        batch = socks_candidates[i : i + 50]
        results = await asyncio.gather(*[check_socks5_proxy(p) for p in batch])
        good_socks.extend([p for p, ok in zip(batch, results) if ok])
        if len(good_socks) >= MAX_PROXY:
            break
        await asyncio.sleep(0.1)
    good_socks = good_socks[:MAX_PROXY]

    log.info("proxies ok: http=%d socks5=%d", len(good_http), len(good_socks))
    return good_http, good_socks


async def github_put_file(session: aiohttp.ClientSession, path: str, content: bytes, message: str):
    """PUT file to GitHub repo via Contents API. Returns True on success."""
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


async def run_cycle():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    async with aiohttp.ClientSession() as session:
        vpn = await collect_vpn(session)
        sub_b64 = base64.b64encode("\n".join(vpn).encode()).decode()
        (OUTPUT_DIR / "subscription.txt").write_text(sub_b64)
        (OUTPUT_DIR / "subscription_raw.txt").write_text("\n".join(vpn) + "\n" if vpn else "")
        log.info("wrote subscription.txt: %d nodes, %d bytes b64", len(vpn), len(sub_b64))

        http_p, socks_p = await collect_proxies(session)
        (OUTPUT_DIR / "http_proxies.txt").write_text("\n".join(http_p) + "\n" if http_p else "")
        (OUTPUT_DIR / "socks5_proxies.txt").write_text("\n".join(socks_p) + "\n" if socks_p else "")
        log.info("wrote http_proxies.txt=%d socks5_proxies.txt=%d", len(http_p), len(socks_p))

        # publish to GitHub if token present
        if GITHUB_TOKEN:
            ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
            await github_put_file(session, "subscription.txt", sub_b64.encode(), f"Update subscription {ts}")
            await github_put_file(session, "http_proxies.txt", (OUTPUT_DIR / "http_proxies.txt").read_bytes(), f"Update http proxies {ts}")
            await github_put_file(session, "socks5_proxies.txt", (OUTPUT_DIR / "socks5_proxies.txt").read_bytes(), f"Update socks5 proxies {ts}")
        else:
            log.info("GITHUB_TOKEN not set, skipping GitHub publish (files are local only)")
        return {"vpn": len(vpn), "http": len(http_p), "socks5": len(socks_p)}


async def main_loop():
    log.info("readall service started, interval=%ss, output=%s", INTERVAL, OUTPUT_DIR)
    while True:
        try:
            result = await run_cycle()
            log.info("cycle done: %s", result)
        except Exception as e:
            log.exception("cycle failed: %s", e)
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    if "--once" in sys.argv:
        asyncio.run(run_cycle())
    else:
        asyncio.run(main_loop())
