# AdGuard Home DoH Smart DNS

Персональный Smart DNS на базе AdGuard Home и nginx. Установка выполняется
одной командой на чистом Ubuntu 24.04 или более новой версии.

Поддерживаются адреса ChatGPT и загрузки OpenAI, Google Gemini и AI Studio,
Claude, Copilot, Perplexity, Grok, Midjourney и Fitbit. Полный список находится
в [`config/policy.csv`](config/policy.csv).

Это не VPN. HTTPS не расшифровывается: nginx использует только TLS SNI и
перенаправляет выбранные домены на исходные HTTPS-серверы.

## Что устанавливается

- AdGuard Home v0.107.78 для DNS и приватного DoH;
- nginx для TLS, SNI-маршрутизации и административной панели;
- сертификат Let's Encrypt через Certbot;
- health-gate: политика включается после 3 успешных TLS-проверок и
  отключается после 2 последовательных ошибок;
- Apple-профиль `.mobileconfig` с адресом DoH.

## Требования

Перед установкой:

1. Сервер Ubuntu 24.04 или новее с публичным IPv4.
2. Доступ root или `sudo`.
3. A-запись домена направлена на IPv4 сервера.
4. Открыты TCP/UDP 53, TCP 80 и TCP 443.

Порт 80 нужен Certbot для первичной выдачи сертификата. После этого nginx
перенаправляет обычный HTTP на HTTPS.

## Установка одной командой

Запустите на сервере:

```bash
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/bootstrap.sh \
  | sudo bash -s -- \
      --domain dns.example.com \
      --public-ip 203.0.113.10 \
      --email admin@example.com
```

Замените:

- `dns.example.com` на свой DNS-домен;
- `203.0.113.10` на публичный IPv4 сервера;
- `admin@example.com` на email для Let's Encrypt.

## Данные после первоначальной установки

При первой установке установщик выводит логин, пароль и оба клиентских адреса:

```text
AdGuard Home admin credentials (save them now):
URL: https://dns.example.com/
Login: admin
Password: <сгенерированный пароль>
Saved locally: /var/lib/pressroll-smart-dns/admin-credentials (mode 0600)
DoH URL: https://dns.example.com/doh/<токен>
mobileconfig: https://dns.example.com/<токен>.mobileconfig
```

Логин всегда `admin`. Пароль генерируется случайно и сохраняется только на
сервере в файле:

```text
/var/lib/pressroll-smart-dns/admin-credentials
```

## Повторный вывод адресов

Если вывод установки потерян, выполните на VPS. Команда читает активный домен и
токен из текущей конфигурации nginx:

```bash
sudo bash -c '
set -e
config=/etc/nginx/sites-enabled/pressroll-smart-dns
domain=$(awk "\$1 == \"server_name\" { sub(/;/, \"\", \$2); print \$2; exit }" "$config")
token=$(grep -oE "location = /doh/[a-f0-9]{32,64}" "$config" | sed "s#location = /doh/##")
printf "DoH URL: https://%s/doh/%s\\n" "$domain" "$token"
printf "mobileconfig: https://%s/%s.mobileconfig\\n" "$domain" "$token"
'
```

Повторный вывод логина и пароля:

```bash
sudo cat /var/lib/pressroll-smart-dns/admin-credentials
```

Пароль и URL содержат секретные данные. Не публикуйте их в GitHub Issues,
чатах или логах общего доступа.

## Подключение клиентов

### Apple: iPhone, iPad, macOS

Откройте адрес `mobileconfig` из вывода установки в Safari и установите
профиль. В профиле уже записан приватный DoH-адрес.

### Другие системы и браузеры

Используйте строку `DoH URL` в настройках пользовательского DNS-over-HTTPS.
После смены DNS очистите локальный DNS-кэш и перезапустите браузер.

Публичный путь `/dns-query` намеренно закрыт и возвращает 404. Работает только
сгенерированный приватный путь `/doh/<токен>`.

## Проверка сервисов

```bash
systemctl status AdGuardHome nginx pressroll-smart-dns-health.timer
journalctl -u pressroll-smart-dns-health.service -n 80 --no-pager
cat /var/lib/pressroll-smart-dns/health-state.json
```

Проверка конфигурации nginx:

```bash
sudo nginx -t
```

## Обновление и откат

Повторный запуск с `--update` обновляет политику и runtime-файлы, сохраняет
пароль AdGuard Home и создаёт резервную копию:

```bash
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/bootstrap.sh \
  | sudo bash -s -- \
      --domain dns.example.com \
      --public-ip 203.0.113.10 \
      --email admin@example.com \
      --update
```

После обновления повторно выведите адреса командой из раздела выше. Резервные
копии хранятся в `/var/backups/pressroll-smart-dns/`.

Откат к последней полной резервной копии:

```bash
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/bootstrap.sh \
  | sudo bash -s -- \
      --domain dns.example.com \
      --public-ip 203.0.113.10 \
      --email admin@example.com \
      --rollback
```

## Локальная проверка без изменений сервера

```bash
./deploy/install.sh \
  --domain dns.example.com \
  --public-ip 203.0.113.10 \
  --email admin@example.com \
  --root /tmp/pressroll-smart-dns \
  --dry-run
```

## Проверки репозитория

```bash
PYTHONPYCACHEPREFIX=/tmp/pressroll-smart-dns-pycache \
  python3 -m unittest discover -s tests -v
python3 tools/check_release.py
bash -n bootstrap.sh deploy/install.sh deploy/lib/common.sh
```

Репозиторий: <https://github.com/evgenykhripach/AdguardHomeDoH>
