#!/usr/bin/env python3
"""readall — автономный сервис сбора, валидации и публикации сетевых конфигураций.

Модуль 1: VPN строго VLESS (vless://), приоритет Reality/TLS.
  - SS (ss://) и VMess (vmess://) полностью исключены.
  - Динамический поиск свежих списков через GitHub Search API
    (запросы vless subscription / free vless / vless raw) + живые
    агрегаторы без Telegram. Мёртвые источники (404/502, 0 VLESS)
    автоматически отбрасываются.
  - Проверка TCP + TLS/Reality handshake, таймаут 3 с, замер задержки.
  - Sticky Pool: узел выбывает только после 2 неудач подряд.
  - Экспорт base64-подписки только из VLESS для Hiddify / Nekobox.

Модуль 2: Прокси для скриптов (HTTP / SOCKS5)
  - парсинг открытых прокси без авторизации
  - проверка реальными запросами
  - http_proxies.txt / socks5_proxies.txt, по одному ip:port на строку

Публикация: файлы в OUTPUT_DIR, при наличии GITHUB_TOKEN — коммиты
в foto-co-zvezdoy/readall через GitHub Contents API.
Токен берётся из окружения /opt/readall/.env (GITHUB_TOKEN),
git remote для пуша не используется.
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
MAX_VPN = int(os.environ.get("MAX_VPN_NODES", "100"))
MAX_PROXY = int(os.environ.get("MAX_PROXIES", "200"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "foto-co-zvezdoy/readall")
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")

# Только проверенные живые seed-источники (проверено 2026-11-06:
# ALIILAPRO — 458 VLESS, Pawdroid — 15 VLESS).
# Всё остальное находится динамически через GitHub Search.
SEED_VLESS_SOURCES = [
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
]

GITHUB_SEARCH_QUERIES = [
    "vless subscription",
    "free vless",
    "vless raw",
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
    """Только vless://. ss://, vmess://, trojan:// отбрасываются."""
    out: list[str] = []
    text = text.strip()
    if not text:
        return out
    if "://" not in text:
        decoded = b64_decode_safe(text)
        if decoded:
            text = decoded
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("vless://"):
            out.append(line)
        elif len(line) > 20 and "://" not in line:
            decoded = b64_decode_safe(line)
            if decoded.startswith("vless://"):
                out.append(decoded.strip())
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def vless_priority(link: str) -> int:
    """2 — Reality, 1 — TLS, 0 — без шифрования."""
    low = link.lower()
    if "reality" in low:
        return 2
    if "security=tls" in low or "tls" in low:
        return 1
    return 0


def parse_host_port(link: str):
    """VLESS only. Return (host, port, use_tls, sni) or None."""
    try:
        parsed = urlparse(link)
        if parsed.scheme != "vless":
            return None
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        query = parsed.query.lower()
        # SNI из параметра sni=, иначе host
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
    """TCP + TLS/Reality handshake, таймаут 3 с. Return latency ms or None."""
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
    """Динамический поиск VLESS-списков через GitHub Search API.

    Ищет репозитории по запросам, затем через Contents API находит
    .txt-файлы в корне и проверяет, есть ли в них vless://.
    Мёртвые (404/502, 0 VLESS) отбрасываются сразу.
    """
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
    # Ограничиваемся первыми 12 репозиториями, чтобы не упираться в rate limit
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
        # также пробуем стандартные пути
        for path in ("sub", "sub.txt", "vless.txt", "vless"):
            candidates.append(f"https://raw.githubusercontent.com/{repo}/main/{path}")
            candidates.append(f"https://raw.githubusercontent.com/{repo}/master/{path}")
        for url in candidates:
            if url in found_urls:
                continue
            text = await fetch_text(session, url)
            if not text:
                continue
            links = parse_vpn_links(text)
            if len(links) >= 3:
                log.info("discovered vless source %s: %d vless", url, len(links))
                found_urls.append(url)
            # не тратим время на остальные файлы этого репо, если уже нашли живой
            if len(found_urls) >= 10:
                break
        if len(found_urls) >= 10:
            break
    return found_urls


def load_state():
    try:
        data = json.loads(STATE_FILE.read_text())
        if isinstance(data, dict):
            # Фильтр протокола: старые ss/vmess/trojan узлы выбрасываются
            active = [x for x in data.get("active", []) if isinstance(x, str) and x.startswith("vless://")]
            if len(active) != len(data.get("active", [])):
                log.info("state filtered to vless only: %d kept", len(active))
            data["active"] = active
            data.setdefault("fails", {})
            data.setdefault("sources", {})
            return data
    except Exception:
        pass
    return {"active": [], "fails": {}, "sources": {}}


def save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    except Exception as e:
        log.warning("cannot save state: %s", e)


async def collect_vpn(session: aiohttp.ClientSession):
    """Sticky Pool, только VLESS, приоритет Reality/TLS."""
    state = load_state()
    active: list[str] = list(state.get("active", []))
    fails: dict[str, int] = dict(state.get("fails", {}))
    source_state: dict[str, dict] = dict(state.get("sources", {}))

    # 1) динамический поиск + seed
    discovered = await discover_vless_sources(session)
    all_sources = list(SEED_VLESS_SOURCES)
    for u in discovered:
        if u not in all_sources:
            all_sources.append(u)
    log.info("vpn sources (seed+discovered): %d", len(all_sources))

    # 2) fetch candidates, отбрасывая мёртвые источники
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
    # источники с 2+ неудачами подряд удаляются из памяти
    source_state = {k: v for k, v in source_state.items() if v.get("fails", 0) < 2}
    seen, uniq = set(), []
    for x in candidates:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    candidates = uniq
    log.info("vpn candidates total (vless only): %d from %d live sources", len(candidates), len(live_sources))

    # 3) check active pool first (sticky)
    kept: list[tuple[int, float, str]] = []  # (priority, latency, link)
    if active:
        results = await asyncio.gather(*[check_vpn_node(x) for x in active])
        for link, lat in zip(active, results):
            if lat is not None:
                fails[link] = 0
                kept.append((vless_priority(link), lat, link))
            else:
                fails[link] = fails.get(link, 0) + 1
                if fails[link] < 2:
                    log.info("vpn sticky keep (fail %d/2): %s", fails[link], link[:60])
                    kept.append((vless_priority(link), 9999.0, link))
                else:
                    log.info("vpn drop after 2 fails: %s", link[:60])
                    fails.pop(link, None)
        log.info("vpn sticky kept: %d / %d", len(kept), len(active))

    # 4) fill pool with fresh candidates that pass, Reality/TLS first
    kept_links = {x for _, _, x in kept}
    fresh = [x for x in candidates if x not in kept_links]
    # сортируем кандидатов: сначала Reality/TLS
    fresh.sort(key=lambda x: -vless_priority(x))
    fresh = fresh[:500]
    for i in range(0, len(fresh), 50):
        if len(kept) >= MAX_VPN:
            break
        batch = fresh[i : i + 50]
        results = await asyncio.gather(*[check_vpn_node(x) for x in batch])
        for link, lat in zip(batch, results):
            if lat is not None and len(kept) < MAX_VPN:
                kept.append((vless_priority(link), lat, link))
                fails[link] = 0
        await asyncio.sleep(0.2)

    # сортировка: приоритет Reality/TLS, затем задержка
    kept.sort(key=lambda t: (-t[0], t[1]))
    final = [x for _, _, x in kept[:MAX_VPN]]
    save_state({
        "active": final,
        "fails": {k: v for k, v in fails.items() if k in final},
        "sources": source_state,
    })
    n_reality = sum(1 for x in final if vless_priority(x) == 2)
    n_tls = sum(1 for x in final if vless_priority(x) == 1)
    log.info("vpn final pool: %d vless (reality=%d tls=%d plain=%d)", len(final), n_reality, n_tls, len(final) - n_reality - n_tls)
    return final


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
        log.info("wrote subscription.txt: %d vless nodes, %d bytes b64", len(vpn), len(sub_b64))

        http_p, socks_p = await collect_proxies(session)
        (OUTPUT_DIR / "http_proxies.txt").write_text("\n".join(http_p) + "\n" if http_p else "")
        (OUTPUT_DIR / "socks5_proxies.txt").write_text("\n".join(socks_p) + "\n" if socks_p else "")
        log.info("wrote http_proxies.txt=%d socks5_proxies.txt=%d", len(http_p), len(socks_p))

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
