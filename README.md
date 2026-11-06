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
- Порядок подписки строгий: FI 6, US 6, DE 6, PL 6,
  затем 6 редких стран по 1 узлу (всего 30). Имена: `🇫🇮 FI | Fast 01`, `🇭🇷 HR | Fast 01`.
- Ровно 6 серверов на страну, не больше не меньше: если после первого прохода
  проверки страна не набрала 6, проверяются остальные кандидаты, а если и этого
  мало — добирается из прошлого пула той же страны.
- Скорость: реальный замер через Xray-core — скачивание 2 МБ через VLESS-туннель
  узла (speed.cloudflare.com), порог 5 Мбит/с. Узел медленнее 5 Мбит/с улетает
  из пула и заменяется из резерва той же страны. Замер делается при каждом
  полном цикле и разовой командой `python app.py --speed-check` для текущего
  пула. 5-минутный мониторинг по-прежнему ловит мёртвые узлы по handshake.
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
- Проверка в два этапа: сначала пинг (TCP + запрос/рукопожатие),
  затем реальный замер скорости — скачивание 1 МБ через прокси
  (speed.cloudflare.com). Прокси медленнее 2 Мбит/с вылетают из списков
  (переменная `PROXY_SPEED_MIN_MBPS`, по умолчанию 2).
  Пинг этого не показывает: порт может отвечать, а трафик не идти.
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
