# readall

Автономный сервис сбора, валидации и публикации сетевых конфигураций.

## Что делает

**Модуль 1 — VPN строго VLESS (vless://)**
- Только VLESS. Shadowsocks (ss://) и VMess (vmess://) полностью исключены.
- Приоритет Reality/TLS.
- Динамический поиск свежих списков через GitHub Search API
  (vless subscription / free vless / vless raw) + живые агрегаторы без Telegram.
  Мёртвые источники (404/502, 0 VLESS) автоматически отбрасываются.
- Проверка: TCP-подключение + TLS/Reality-handshake, таймаут 3 с, замер задержки.
- Geo: страна узла по IP (ip-api.com, кэш). Blacklist: RU, UA, CN, IR,
  BY, KZ, UZ, AM, AZ, KG, TJ, MD — полностью исключены из всех списков.
- Порядок подписки строгий: DE 6, FI 6, PL 6, NL 6, SE 6, US 6,
  затем 6 редких стран по 1 узлу (всего 42). Имена: `🇩🇪 DE | Fast 01`, `🇭🇷 HR | Fast 01`.
- Редкие страны случайные и меняются ровно раз в сутки (seed = дата UTC).
  Если редкая страна перестаёт отвечать, монитор заменяет её на другую
  случайную страну сразу, не дожидаясь суток.
- Sticky Pool + 5-минутный мониторинг (`MONITOR_INTERVAL=300`):
  узел заменяется только после 2 неудач подряд или 2 медленных проверок
  подряд. Критерий медленного узла: задержка handshake >2000 мс
  (≈ <1.5 Мбит/с для блока 256 КБ) или рост задержки в 3+ раза от базовой.
  При замене подписка сразу пушится в GitHub.
- Экспорт: `subscription.txt` — base64-подписка только из VLESS для Hiddify / Nekobox.

**Модуль 2 — Прокси для скриптов (HTTP / SOCKS5)**
- Парсинг открытых прокси без авторизации.
- Проверка реальными запросами (HTTP) и SOCKS5-handshake.
- Geo-фильтр по тому же blacklist, сортировка по пингу.
- `http_proxies.txt` и `socks5_proxies.txt` — по одному `ip:port` на строку.

## Файлы на выходе

- `subscription.txt` — base64-подписка
- `http_proxies.txt`
- `socks5_proxies.txt`

## Ссылки (GitHub, ветка main)

- Подписка: https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/subscription.txt
- HTTP-прокси: https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/http_proxies.txt
- SOCKS5-прокси: https://raw.githubusercontent.com/foto-co-zvezdoy/readall/main/socks5_proxies.txt

## Запуск

```bash
python3 -m venv /opt/readall/venv
/opt/readall/venv/bin/pip install -r requirements.txt
cp .env.example /opt/readall/.env  # при необходимости указать GITHUB_TOKEN
systemctl enable --now readall
```

Интервал обновления по умолчанию — 1800 с (30 минут), переменная `COLLECT_INTERVAL`.
Публикация в GitHub выполняется сервисом, только если задан `GITHUB_TOKEN`
с правами записи в репозиторий. Без токена файлы обновляются локально
в `/opt/readall/output/`.
