# Прокси в скриптах

Привет! Коротко о том, как пользоваться прокси из readall в своих скриптах.
Всё просто: вставляешь в скрипт ссылку на список, скрипт скачивает список,
берёт первый прокси и работает через него. Списки отсортированы по скорости
и пингу, так что первый — самый быстрый. Если прокси недоступен, скрипт
просто берёт следующий из списка и пробует снова.

## Ссылки на списки

| Что | Ссылка |
|---|---|
| HTTP-прокси | https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt |
| SOCKS5-прокси | https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/socks5_proxies.txt |
| VLESS-подписка (для VPN-клиентов) | https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/subscription.txt |

Формат списков: чистый `ip:port`, без логина и пароля, по одному в строке.
Списки обновляются каждые 30 минут сами, в скрипте их стоит перекачивать
раз в полчаса.

## Как это работает

1. Вставляешь в скрипт ссылку на список прокси.
2. Скрипт скачивает список.
3. Берёт первый прокси — он самый быстрый, списки отсортированы
   по скорости и пингу.
4. Делает запрос через этот прокси.
5. Если прокси недоступен или запрос упал — берёт следующий из списка
   и пробует снова. И так пока не получится или пока не кончатся попытки.

## Готовый пример

```python
import requests

PROXY_LIST_URL = "https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt"

def load_proxies(url):
    return requests.get(url, timeout=15).text.split()

def get(url, proxies, tries=10):
    for proxy in proxies[:tries]:
        try:
            return requests.get(
                url,
                proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
                timeout=10,
            )
        except requests.RequestException:
            continue
    raise RuntimeError("все прокси отвалились")

proxies = load_proxies(PROXY_LIST_URL)
print(get("https://httpbin.org/ip", proxies).text)
```

Для SOCKS5 то же самое, только схема другая и нужен PySocks
(`pip install requests[socks]`):

```python
proxies = {"http": "socks5://ip:port", "https": "socks5://ip:port"}
```

С `httpx` аналогично: `httpx.get(url, proxy="http://ip:port")`,
для SOCKS5 — `pip install httpx[socks]` и `proxy="socks5://ip:port"`.

## Готовый хелпер

В этом же репозитории лежит `proxy_helper.py` — там уже всё это сделано.
Подключаешь и пользуешься:

```python
from proxy_helper import get

r = get("https://httpbin.org/ip", kind="http")    # HTTP-прокси
r = get("https://httpbin.org/ip", kind="socks5")  # SOCKS5-прокси
print(r.text)
```

Хелпер сам скачивает свежий список, берёт первый рабочий прокси,
а если прокси умер — идёт дальше по списку. Зависимости: `requests`,
для SOCKS5 ещё `pip install requests[socks]`.

## Как проверяются прокси

Каждый прокси в списке проходит две проверки: сначала пинг, потом
реальное скачивание 1 МБ через прокси. Медленнее 0,5 Мбит/с —
вылетает из списка. Поэтому в списках только то, что реально работает,
и первый — самый быстрый.

## VLESS-подписка

Если нужен VPN, а не прокси для скриптов: ссылка на подписку — третья
в таблице выше. В клиенте (Hiddify, Nekobox и т.п.) добавляешь подписку
по URL, вставляешь ссылку и обновляешь.
