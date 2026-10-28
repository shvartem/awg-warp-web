# awg-warp-web

Статическая страница, которая регистрирует бесплатный аккаунт Cloudflare WARP и собирает конфиг для AmneziaWG. Работает на телефоне и компьютере.

## Что умеет

- **Два способа получить ключ.**
  - *Сервер Santa*: запрос идёт к генератору Santa через Worker. Приватный ключ создаёт Santa, и у него остаётся копия.
  - *Этот браузер*: пара ключей X25519 генерируется на устройстве. В Cloudflare через ваш Worker уходит только публичный ключ.
- **Обфускация AmneziaWG.** Значения по умолчанию: Jc 120, Jmin 23, Jmax 911, S1/S2 0, H1–H4 1–4, MTU 1280 и пакет `I1`, похожий на QUIC Initial. Все значения можно менять.
- **Выбор endpoint.** Десять известных адресов Cloudflare WARP, свой адрес, порты 500, 2408, 1701, 4500.
- **Сеть.** DNS на выбор (Cloudflare, Cloudflare Security и Family, AdGuard и AdGuard Family, Google, Quad9 или свои серверы), AllowedIPs, MTU, keepalive, отключение IPv6.
- **Выдача.** Копирование, скачивание файла `warp_<dns>[_santa].conf` (например, `warp_adgf_santa.conf`; имя не длиннее 15 символов, как требуют приложения AmneziaWG), отправка файла в приложение через системное меню «Поделиться» (Android и iOS).
- Если поменять параметры после получения, конфиг пересобирается без новой регистрации. Настройки запоминаются в браузере, ключи не сохраняются.

## Устройство

```
site/                    статическая страница (GitHub Pages)
  index.html, style.css, app.js
  lib/warp.js            значения по умолчанию, разбор ответа, сборка конфига
  lib/x25519.js          генерация ключей WireGuard в браузере
  config.js              адрес Worker; в репозитории пустой, при деплое пишется из WORKER_URL
worker/                  Cloudflare Worker: CORS-прокси
  src/index.js           GET /santa (→ SANTA_URL) и POST /reg (→ API Cloudflare), других адресов нет
tests/                   node tests/run.mjs, node tests/worker.mjs
```

Santa и API Cloudflare не отдают CORS-заголовки, поэтому браузер не пускает к ним страницу напрямую. Все запросы страница отправляет через Worker.

## Настройки вне репозитория

В коде нет ни адреса генератора Santa, ни адресов вашей страницы и Worker. Всё задаётся переменными окружения:

| Имя | Где задать | Что это |
|---|---|---|
| `WORKER_URL` | GitHub: Settings → Secrets and variables → Actions → **Variables** | Адрес Worker. Без него деплой страницы останавливается с ошибкой |
| `SANTA_URL` | Cloudflare: Worker → Settings → Variables and Secrets, тип **Secret** | Адрес генератора Santa |
| `ALLOWED_ORIGINS` | там же, тип Text или Secret | Адрес страницы, например `https://user.github.io`. Пусто или `*` — разрешено всем |

Если Worker деплоится через GitHub Actions, задайте `SANTA_URL` как секрет репозитория, а `ALLOWED_ORIGINS` как переменную. Workflow передаст их в Worker сам.

Адрес Worker всё равно виден в опубликованном `config.js`: браузер должен знать, куда отправлять запросы. Скрыть его на статическом сайте нельзя. От чужих сайтов Worker защищает `ALLOWED_ORIGINS`. Адрес Santa хранится только в Worker, и в браузер он не попадает.

## Развёртывание

### 1. GitHub Pages

1. Создайте репозиторий и загрузите в него эти файлы (ветка `main`).
2. Откройте **Settings → Pages → Build and deployment → Source** и выберите **GitHub Actions**.
3. Задайте переменную `WORKER_URL` (см. выше). После push страница появится по адресу `https://<user>.github.io/<repo>/`.

### 2. Cloudflare Worker (бесплатный план: 100 000 запросов в день)

Вариант через панель: Workers & Pages → Create → Start with Hello World, затем Edit code, вставить `worker/src/index.js` и нажать Deploy. После этого задать `SANTA_URL` и `ALLOWED_ORIGINS` в Settings → Variables and Secrets.

Вариант через терминал:

```bash
cd worker
npx wrangler login
npx wrangler secret put SANTA_URL
npx wrangler secret put ALLOWED_ORIGINS
npx wrangler deploy
```

Вариант через GitHub Actions:

1. Создайте токен в Cloudflare → My Profile → API Tokens по шаблону **Edit Cloudflare Workers**.
2. Добавьте в репозиторий секреты `CLOUDFLARE_API_TOKEN` и `SANTA_URL`, а также переменную `ALLOWED_ORIGINS`. Если у вас несколько аккаунтов Cloudflare, добавьте ещё секрет `CLOUDFLARE_ACCOUNT_ID`.
3. Запустите **Actions → Deploy Cloudflare Worker → Run workflow**.

### 3. Связать страницу с Worker

Задайте переменную `WORKER_URL` и перезапустите **Deploy to GitHub Pages**. Адрес Worker можно также ввести прямо на странице, в разделе «Прокси».

## Ограничения и риски

- **Режим Santa.** Santa знает ваш приватный ключ. Он может расшифровать трафик до Cloudflare и использовать аккаунт.
- **Режим «Этот браузер».** Cloudflare может отклонять регистрацию. Официальный клиент и wgcf подделывают TLS-отпечаток Android (uTLS), а Worker так не умеет. Если `/reg` возвращает ошибку, используйте режим Santa или [wgcf](https://github.com/ViRb3/wgcf) и вставьте ключи вручную.
- **Версия API.** Используется `v0a5641` с заголовками клиента 6.38.9, как в wgcf. Если Cloudflare сменит версию, обновите константы в `worker/src/index.js`.
- **Совместимость I1.** Параметр `I1` понимают AmneziaWG 1.5 и новее. Старые клиенты выдадут ошибку, тогда отключите I1.
- **Проверка endpoint.** Браузер не может проверить, отвечает ли UDP-endpoint. Если туннель не подключается, переключайте адрес и порт вручную.

## Тесты

```bash
node tests/run.mjs      # X25519 по RFC 7748 и сверка с node:crypto, сборка конфига
node tests/worker.mjs   # Worker с подменённым fetch
```

Локальный запуск страницы: `npx serve site` или `python3 -m http.server -d site`.

Проект неофициальный и не связан с Cloudflare. Используя WARP, вы принимаете [условия Cloudflare](https://www.cloudflare.com/application/terms/).
