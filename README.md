# adguardhome-doh

Нейтральный персональный Smart DNS на базе AdGuard Home, nginx и приватного
tokenized DoH. Проект поддерживает только чистую установку и обновление начиная
с `v1.0.0`; миграции старых инсталляций не выполняются.

## Установка

На чистом Ubuntu 24.04+ выполните:

```bash
curl --fail --silent --show-error --location \
  https://raw.githubusercontent.com/evgenykhripach/AdguardHomeDoH/main/bootstrap.sh \
  | sudo bash
```

Мастер последовательно запросит домен, публичный IPv4, email для Let's Encrypt
и сервисы. Каждый ответ проверяется сразу. Перед изменениями показываются
параметры и запрашивается подтверждение. Для CI доступны флаги:

```bash
sudo bash deploy/install.sh --domain dns.example.com \
  --public-ip 203.0.113.10 --email admin@example.com \
  --services chatgpt,claude --yes
```

В интерактивном мастере сервисы выбираются по категориям, поэтому на экране не
показывается длинный список из 79 строк. Введите номер категории, затем номера
сервисов через пробел. Команды `A`/`N` выбирают или снимают все сервисы текущей
категории, `B` возвращает к категориям, `/текст` ищет по названию и ID, `D`
выбирает стандартный набор, `X` открывает экспериментальные сервисы, `Y`
показывает итог с числом уникальных доменов, `C` отменяет выбор.

Пример: `1` → `1 2` → `B` → `Y` → `y` включает ChatGPT и Claude после
предварительного просмотра.

`--dry-run --root PATH` рендерит конфигурацию без записи на сервер. Стадии
показываются как 0/5/20/35/50/65/75/85/95/100 процентов; в TTY используется
цветная ANSI-полоса, без TTY печатаются отдельные строки.

## Каталог сервисов

Каталог состоит из `config/services.csv`, `domains.csv`,
`service-domains.csv` и `service-probes.csv`. В нём 206 уникальных доменов,
включая все 178 строк из GeoHide и 60 прежних политик с сохранением `fqdn` или
`suffix`. Общие домены остаются активными, пока здоров хотя бы один выбранный
сервис. По умолчанию включены ChatGPT, Claude, Gemini, Microsoft Copilot,
GitHub Copilot и Grok. Экспериментальные и чувствительные группы выключены и
не включаются командой «выбрать все». Context7 доступен отдельным сервисом
`context7` в категории «Разработка»: он включает `context7.com` и проверяет
официальную MCP-точку `mcp.context7.com`.

## Экран после установки

Успешная установка всегда выводит URL админки, логин, пароль, tokenized DoH,
ссылку на Apple `.mobileconfig`, пути credentials и лога, а также команду:

```text
Password: <пароль администратора>
sudo adguardhome-doh
```

Секреты хранятся только в root-only JSON:

```text
/var/lib/adguardhome-doh/admin-credentials.json  (0600)
/var/lib/adguardhome-doh/doh-token                (0600)
/var/lib/adguardhome-doh/install.json             (0600)
/var/lib/adguardhome-doh/enabled-services.json    (0600)
/var/log/adguardhome-doh/                         (каталог 0700, файлы 0600)
```

## Менеджер

`sudo adguardhome-doh` открывает только интерактивное русское меню:

1. Доступ к данным;
2. Изменить сервисы;
3. Проверка системы;
4. Проверить и установить обновление;
5. Откатить последнее обновление;
6. Выход.

Изменение сервисов использует тот же двухуровневый селектор, что и установщик:
сначала категории, затем сервисы; доступен поиск `/текст`, `D` для стандартных
сервисов, `X` для экспериментальных и `Y` для итогового подтверждения. Оно
показывает количество доменов до и после, создаёт полный
backup, рендерит все runtime-файлы, проверяет `AdGuardHome --check-config` и
nginx в правильных `http`/`stream` контекстах, затем атомарно активирует staging.
При ошибке автоматически восстанавливается backup.

Health-gate проверяет TLS-пробы сервисов с максимумом 8 параллельных задач,
хранит состояние по service ID и применяет пороги 3 успеха / 2 ошибки. Для
ChatGPT отдельно проверяется `files.oaiusercontent.com`.

## Сеть и клиенты

AdGuard Home слушает DNS только на loopback. Наружу публикуются HTTPS-админка,
tokenized DoH `/doh/<token>` и приватный `.mobileconfig`; публичный `/dns-query`
закрыт. HTTPS не расшифровывается: nginx использует TLS SNI.

## Stable update и rollback

Bootstrap получает последний non-draft/non-prerelease GitHub Release, проверяет
semver, SHA-256, совпадение `VERSION` с тегом и обязательные файлы архива. Новые
service ID после обновления остаются выключенными; новые домены уже включённых
сервисов подключаются автоматически. Менеджер сохраняет credentials, token и
выбранные сервисы. Полный backup хранится в `/var/backups/adguardhome-doh/`.

## Проверки

```bash
PYTHONPYCACHEPREFIX=/tmp/adguardhome-doh-pycache \
  python3 -m unittest discover -s tests -v
python3 tools/check_release.py
bash -n bootstrap.sh deploy/install.sh deploy/lib/common.sh deploy/lib/ui.sh
git grep -n -i 'старое имя'  # должен вернуть пустой результат
```

Полный smoke-тест Ubuntu 26.04:

```bash
docker run --rm -v "$PWD:/repo:ro" ubuntu:26.04 \
  /repo/tests/ubuntu_26_04_smoke.sh /repo
```

Публикация Release, push и применение на VPS выполняются только после отдельного
разрешения владельца проекта.
