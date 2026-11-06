# Как пользоваться readall

Сервис `readall` каждые 30 минут собирает, проверяет и публикует свежие
VLESS-узлы и прокси. Всё ниже — готовые ссылки, ничего скачивать
вручную не нужно: списки обновляются сами.

## Ссылки

| Что | Ссылка |
|---|---|
| VLESS-подписка (для Hiddify / Nekobox / Streisand) | https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/subscription.txt |
| HTTP-прокси | https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt |
| SOCKS5-прокси | https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/socks5_proxies.txt |

Количество меняется каждый цикл: мёртвые узлы вылетают, новые добавляются.
По состоянию на цикл 06.11.2026 23:08 UTC: VLESS — 20 узлов, HTTP — 14,
SOCKS5 — 4 (тогда порог был 2 Мбит/с; сейчас 0,5 Мбит/с, списки длиннее).

Общие правила для всех списков:
- Из всех списков исключены RU, UA, CN, IR и страны СНГ
  (BY, KZ, UZ, AM, AZ, KG, TJ, MD).
- Списки обновляются каждые 30 минут автоматически.

## VLESS-подписка (VPN)

1. В клиенте (Hiddify, Nekobox, Streisand и т.п.): добавить подписку по URL.
2. Вставить ссылку на `subscription.txt` (первая строка таблицы выше).
3. Обновить подписку — узлы появятся списком.

Что внутри:
- Только VLESS, приоритет Reality/TLS.
- Порядок строгий: Финляндия 6, США 6, Германия 6, Польша 6,
  дальше 6 случайных стран по 1 узлу. Имена вида `🇫🇮 FI | Fast 01`.
- Каждый узел реально проверен: handshake + скачивание 2 МБ через туннель,
  медленнее 5 Мбит/с — вылетает из пула.
- Редкие страны меняются раз в сутки.
- Обновляйте подписку в клиенте регулярно (или включите автообновление),
  чтобы подхватывать свежие узлы.

## HTTP-прокси

Формат списка: чистый `ip:port`, без логина и пароля, по одному в строке,
отсортированы по пингу (самые быстрые сверху).

### Python + requests

```python
import requests

proxies = {
    "http": "http://94.78.67.171:80",
    "https": "http://94.78.67.171:80",
}
r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
print(r.text)
```

### Python + httpx

```python
import httpx

r = httpx.get("https://httpbin.org/ip",
              proxy="http://94.78.67.171:80", timeout=10)
print(r.text)
```

### curl

```bash
curl -x http://94.78.67.171:80 https://httpbin.org/ip
```

### Браузер

В настройках браузера или системы (или через расширение вроде FoxyProxy):
тип — HTTP, адрес и порт — из списка. Логин и пароль не нужны.

## SOCKS5-прокси

Формат тот же: `ip:port`, без авторизации.

### Python + requests

Нужен PySocks: `pip install requests[socks]`.

```python
import requests

proxies = {
    "http": "socks5://46.232.249.209:40001",
    "https": "socks5://46.232.249.209:40001",
}
r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
print(r.text)
```

### Python + httpx

`pip install httpx[socks]`, дальше `proxy="socks5://ip:port"`.

### curl

```bash
curl --socks5 46.232.249.209:40001 https://httpbin.org/ip
```

## Списки в скриптах и ротация

Списки можно скачивать прямо в скрипте — они всегда свежие:

```python
import requests

def load_proxies(url):
    return requests.get(url, timeout=15).text.split()

http_proxies = load_proxies(
    "https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt"
)
socks5_proxies = load_proxies(
    "https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/socks5_proxies.txt"
)
```

Главное правило: публичные прокси дохнут в любой момент, поэтому нельзя
брать один захардкоженный адрес — нужны проверка и ротация. Готовый
хелпер лежит в этом же репозитории: `proxy_helper.py`.

```python
from proxy_helper import get, session, get_working_proxy

# Один запрос через случайный рабочий прокси (с ротацией при ошибках)
r = get("https://httpbin.org/ip", kind="http")    # HTTP-прокси
r = get("https://httpbin.org/ip", kind="socks5")  # SOCKS5-прокси
print(r.text)

# Серия запросов через один рабочий прокси
s = session(kind="http")
print(s.get("https://httpbin.org/ip").text)

# Просто найти рабочий прокси
print(get_working_proxy(kind="socks5"))
```

Зависимости хелпера: `requests`, для SOCKS5 ещё `pip install requests[socks]`.

## Как проверяются прокси

Каждый прокси в списках проходит две проверки:
1. **Пинг** — TCP-подключение и пробный запрос (HTTP) или рукопожатие (SOCKS5).
2. **Скорость по-настоящему** — скачивание 1 МБ через прокси
   (speed.cloudflare.com). Медленнее 0,5 Мбит/с — вылетает из списка.

Пинг этого не показывает: порт может отвечать, а трафик через прокси
не идти или ползти. Именно поэтому списки короткие: из сотен кандидатов
после обеих проверок остаются десятки. Зато то, что в списке, реально работает.

## Важные правила

- **Не для аккаунтов и денег.** Не используйте эти прокси для Steam,
  FunPay, банков и любых логинов: чужой IP может быть в чёрных списках,
  а аккаунт могут забанить за подозрительный вход.
- **HTTPS через HTTP-прокси всё равно шифруется.** Прокси видит только
  адрес сайта, содержимое запроса — нет (CONNECT-туннель).
- **Не долбите один прокси** сотнями запросов подряд — его быстро забанят
  на целевом сайте. Меняйте прокси каждые N запросов или при ошибке.
- Если сайт отдаёт 403 / капчу через прокси — это нормально для
  публичных IP, просто возьмите другой.
- В долгих скриптах перекачивайте списки раз в 30 минут (в хелпере
  кэш живёт 30 минут) — прокси умирают, а сервис публикует свежие.
