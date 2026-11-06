"""Хелпер для работы с прокси из readall.

Списки берутся с GitHub (обновляются каждые 30 минут):
  HTTP:   https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt
  SOCKS5: https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/socks5_proxies.txt

Формат списков: чистый ip:port, без авторизации, по пингу (быстрые сверху).

Зависимости: requests. Для SOCKS5 нужен ещё PySocks:
    pip install requests[socks]

Пример:
    from proxy_helper import get, load_proxies

    r = get("https://httpbin.org/ip", kind="http")
    print(r.text)
"""

import random
import time

import requests

URLS = {
    "http": "https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt",
    "socks5": "https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/socks5_proxies.txt",
}

_cache = {}  # kind -> (loaded_at, [proxies])


def load_proxies(kind="http", max_age=1800):
    """Скачать свежий список прокси. Кэш живёт max_age секунд."""
    kind = kind.lower()
    if kind not in URLS:
        raise ValueError("kind должен быть 'http' или 'socks5'")
    now = time.time()
    if kind in _cache and now - _cache[kind][0] < max_age:
        return _cache[kind][1]
    r = requests.get(URLS[kind], timeout=15)
    r.raise_for_status()
    proxies = [line.strip() for line in r.text.split() if line.strip()]
    _cache[kind] = (now, proxies)
    return proxies


def _proxies_dict(proxy, kind):
    scheme = "http" if kind == "http" else "socks5"
    return {"http": f"{scheme}://{proxy}", "https": f"{scheme}://{proxy}"}


def check_proxy(proxy, kind="http", timeout=5):
    """Проверить один прокси: вернуть True, если через него открывается сайт."""
    try:
        r = requests.get(
            "https://httpbin.org/ip",
            proxies=_proxies_dict(proxy, kind),
            timeout=timeout,
        )
        return r.status_code == 200
    except requests.RequestException:
        return False


def get_working_proxy(kind="http", tries=10, timeout=5):
    """Найти случайный рабочий прокси из списка. Кидает RuntimeError, если не нашли."""
    proxies = load_proxies(kind)
    random.shuffle(proxies)
    for proxy in proxies[:tries]:
        if check_proxy(proxy, kind, timeout):
            return proxy
    raise RuntimeError(f"не нашли рабочий {kind}-прокси за {tries} попыток")


def get(url, kind="http", tries=5, timeout=10, **kwargs):
    """GET-запрос через случайный рабочий прокси, с ротацией при ошибках."""
    proxies = load_proxies(kind)
    tried = set()
    for _ in range(tries):
        proxy = random.choice(proxies)
        if proxy in tried:
            continue
        tried.add(proxy)
        try:
            return requests.get(
                url, proxies=_proxies_dict(proxy, kind), timeout=timeout, **kwargs
            )
        except requests.RequestException:
            continue
    raise RuntimeError(f"все {kind}-прокси отвалились ({tries} попыток)")


def session(kind="http", tries=5, timeout=10):
    """requests.Session с рабочим прокси (удобно для серии запросов)."""
    proxy = get_working_proxy(kind, tries=tries, timeout=timeout)
    s = requests.Session()
    s.proxies.update(_proxies_dict(proxy, kind))
    s._proxy_used = proxy
    return s


if __name__ == "__main__":
    for kind in ("http", "socks5"):
        proxies = load_proxies(kind)
        print(f"{kind}: загружено {len(proxies)} прокси, первый: {proxies[0]}")
    proxy = get_working_proxy("http")
    print("рабочий HTTP-прокси:", proxy)
    print(get("https://httpbin.org/ip", kind="http").text)
