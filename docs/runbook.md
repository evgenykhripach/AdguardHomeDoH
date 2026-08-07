# Runbook развёртывания

## Предварительная проверка

1. Убедитесь, что `dns.pressroll.ru` имеет только A `89.125.113.107`, без AAAA.
2. Проверьте страну/ASN/репутацию IPv4 и вход на нужные сервисы с VPS.
3. Зафиксируйте существующий SSH-порт и текущие nftables/systemd-сервисы. Установщик
   создаёт только `table inet dohdns` и не должен удалять чужие правила.
4. Выполните локальные тесты и dry-run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/*.py
bash -n deploy/bin/*.sh
deploy/bin/install.sh --inventory inventory.production.json --domain-csv domains/domains.csv --register-unsafely-without-email --dry-run
```

## Установка

Скопируйте checkout на Ubuntu 24.04. Для воспроизводимой установки можно передать
заранее проверенный linux-amd64 бинарник и его SHA256:

```bash
sudo deploy/bin/install.sh \
  --inventory inventory.production.json \
  --domain-csv domains/domains.csv \
  --prebuilt-binary /tmp/sniproxy-linux-amd64 \
  --prebuilt-sha256 HEX_SHA256 \
  --register-unsafely-without-email
```

Без prebuilt-флагов установщик скачивает закреплённые исходники и Go, проверяет
SHA256 и собирает бинарник. Certbot использует HTTP-01; порт 80 и A-запись должны
быть доступны извне.

## Verify

```bash
systemctl --no-pager --full status sniproxy dohdns-nftables.service dohdns-geoip-update.timer
ss -lntup | grep -E ':(53|80|443|853|9090)\b'
nft list table inet dohdns
openssl s_client -connect dns.pressroll.ru:853 -servername dns.pressroll.ru </dev/null
curl --http2 --fail 'https://dns.pressroll.ru/dns-query?name=example.com&type=A' -H 'accept: application/dns-json'
dig @89.125.113.107 openai.com A
dig @89.125.113.107 example.com A
dig @89.125.113.107 openai.com AAAA
dig @89.125.113.107 openai.com HTTPS
certbot renew --dry-run
```

Allowlist-домен должен вернуть `89.125.113.107`, обычный домен — исходный адрес,
а AAAA для проксируемого домена не должен вести в обход VPS. Проверьте, что UDP
443/853 закрыт, сайт через прокси показывает оригинальный TLS-сертификат, SSE и
WebSocket работают. После `systemctl reboot` повторите проверки автозапуска; reboot
выполняйте только в согласованное окно обслуживания.

Финальные тесты обязательны из домашней и мобильной сети РФ. Из внешней сети
проверьте отказ GeoIP. Не считайте локальные тесты доказательством внешней доступности.

## Update и rollback

Отредактируйте `domains/domains.csv`, проверьте валидатором и установите новую
генерацию. Установленная копия автономна:

```bash
sudo /usr/local/libexec/dohdns/update.sh --domain-csv /path/to/domains.csv
sudo /usr/local/libexec/dohdns/rollback.sh
```

Экстренный rollback для клиентов: удалить профиль/ручной DNS и вернуть автоматический
DNS. На сервере остановить `sniproxy`, не удаляя чужие nftables-таблицы. Полное
удаление A-записи выполняется в Beget только после возврата клиентов на обычный DNS.

