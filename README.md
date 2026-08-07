# Pressroll Smart DNS

Персональный Smart DNS на `dns.pressroll.ru`: обычные DNS-ответы идут напрямую,
а домены из allowlist получают адрес VPS и проходят через прозрачный TLS/SNI proxy.
DoH и DoT шифруют DNS-запрос, но обход для выбранных сервисов обеспечивает именно
SNI-прокси. Содержимое HTTPS не расшифровывается.

## Состав

- native `mosajjal/sniproxy` v2.3.0, Ubuntu 24.04 и systemd;
- DNS UDP/TCP 53, DoH `/dns-query`, DoT 853, TLS/SNI TCP 443;
- nginx TCP 80 только для ACME HTTP-01 и перенаправления;
- GeoIP-доступ для РФ, IPv4-only ответы и per-IP nftables rate limits;
- версионированные конфигурации и транзакционный rollback.

## Быстрый запуск

```bash
python3 -m unittest discover -s tests -v
deploy/bin/install.sh \
  --inventory inventory.production.json \
  --domain-csv domains/domains.csv \
  --register-unsafely-without-email \
  --dry-run
```

После dry-run выполните ту же команду от `root` без `--dry-run`. Полная процедура,
проверка и откат находятся в [runbook](docs/runbook.md). Настройка Apple, Android,
Windows, роутеров и консолей — в [client setup](docs/client-setup.md). Источники и
правила allowlist зафиксированы в [domain policy](docs/domain-policy.md).

## Важные ограничения

Это не VPN. Smart DNS не проксирует произвольный UDP, hardcoded IP, обязательный
QUIC/ECH и соединения на порты, которые не слушает прокси. Регион аккаунта и
политики конкретного сервиса он не меняет. Подробности: [privacy and limitations](docs/privacy-and-limitations.md).
