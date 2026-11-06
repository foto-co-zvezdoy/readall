# readall

Автономный сервис сбора, валидации и публикации сетевых конфигураций.

## Что делает

**Модуль 1 — VPN для приложения (VLESS / VMess / Shadowsocks)**
- Сбор свежих публичных ссылок из открытых raw-списков на GitHub (без Telegram).
- Проверка: TCP-подключение + TLS-handshake, таймаут 3 с, замер задержки.
- Sticky Pool: активный пул фиксируется, узел выбывает только после 2 неудач подряд.
- Экспорт: `subscription.txt` — base64-подписка для Hiddify / Nekobox.

**Модуль 2 — Прокси для скриптов (HTTP / SOCKS5)**
- Парсинг открытых прокси без авторизации.
- Проверка реальными запросами (HTTP) и SOCKS5-handshake.
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
