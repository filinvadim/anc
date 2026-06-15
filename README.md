# anc-watch

Мониторинг статуса дела о гражданстве Румынии на сайте ANC (`cetatenie.just.ro`)
с письмом на почту, когда дело решено.

По умолчанию следит за досье **10226/RD/2023** (ст. 11, *redobândire*) и шлёт письмо
на `test@test.me`.

## Что делает

На каждой проверке скрипт:

1. **пробивает анти-бот стену.** Домен отдаёт `503` + JS-страницу
   «Verifying your browser…», которая исполняет SHA1 proof-of-work. Скрипт решает
   этот PoW на чистом Python (без браузера): берёт 40-символьный токен `c`,
   `n1 = int(c[0],16)`, перебирает `i` пока `sha1(c+i)[n1]==0xB0 && [n1+1]==0x0B`,
   ставит cookie `res=<c><i>`. Проверка stateless — один cookie открывает весь домен;
2. на `/stadiu-dosar/` **динамически** находит свежий `Art-11-2023-Update-<дата>.pdf`
   (дата в имени меняется ~раз в неделю — ссылка не хардкодится);
3. качает и парсит PDF (`pypdf`), находит строку дела и читает колонку **SOLUTIE**.
   Номер приказа вида `<n>/P/<год>` = дело решено;
4. при решении подтягивает ссылку на сам приказ из `/ordine-articolul-1-1/`;
5. держит state-файл, чтобы алерт «решено» ушёл **ровно один раз**.

Колонки таблицы: `NR. DOSAR | DATA ÎNREGISTRĂRII | TERMEN | SOLUTIE`.

## Быстрый старт (Docker)

```bash
cd anc-watch
cp .env.example .env          # впишите SMTP-доступ (см. ниже)
docker compose up -d --build
docker compose logs -f        # смотреть проверки
```

Контейнер крутится в фоне (`--loop`) и проверяет раз в `CHECK_INTERVAL` секунд
(по умолчанию раз в сутки). State лежит в named-volume `anc-state`, поэтому
повторного письма после рестарта не будет.

### Почта

`pm.me` (ProtonMail) не даёт обычный SMTP, поэтому **отправлять** надо через любой
доступный релей. Проще всего Gmail + App Password:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USER=you@gmail.com
SMTP_PASS=app_password_16_chars
ALERT_FROM=you@gmail.com
ALERT_TO=test@test.me
```

Если `SMTP_HOST` пуст — скрипт работает в **DRY-RUN**: ничего не шлёт, только
печатает письмо в лог (удобно для проверки).

## Локальный запуск без Docker

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python anc_watch.py --once --dry-run     # один прогон, письмо в консоль
```

## Переменные окружения

| Переменная | По умолчанию       | Назначение |
|---|--------------------|---|
| `ALERT_TO` | `test@test.me`     | получатель (можно несколько через запятую) |
| `ALERT_FROM` | —                  | адрес отправителя |
| `SMTP_HOST/PORT/USER/PASS` | —                  | SMTP-релей; пусто → DRY-RUN |
| `SMTP_SECURITY` | `starttls`         | `starttls` / `ssl` / `none` |
| `ANC_DOSSIER` | `10226/RD/2023`    | какое дело отслеживать |
| `ANC_ARTICLE` / `ANC_YEAR` | `11` / `2023`      | статья и год (выбор PDF) |
| `CHECK_INTERVAL` | `86400`            | пауза между проверками (сек) |
| `NOTIFY_ON_START` | `1`                | прислать стартовое письмо на первом прогоне |
| `ALWAYS_NOTIFY` | `0`                | слать письмо каждый прогон, а не только при изменении |
| `NOTIFY_ON_ERROR` | `1`                | письмо, если сайт не читается N раз подряд |
| `STATE_FILE` | `/data/state.json` | файл состояния |

## Когда придёт письмо

- **разово при решении:** в SOLUTIE появился `<n>/P/<год>` → тема `✅ … ОРДИН … — дело решено!`;
- стартовое (один раз) — подтверждает, что монитор жив;
- (опц.) при длительной недоступности сайта.

## Команды

```bash
docker compose up -d --build   # запустить/пересобрать
docker compose logs -f         # логи
docker compose down            # остановить (state сохранится в volume)
docker compose run --rm anc-watch --once --dry-run   # разовый тестовый прогон
docker volume inspect anc-watch_anc-state            # где лежит state
```
