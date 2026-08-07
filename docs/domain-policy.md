# Политика доменов

Список от 7 августа 2026 года намеренно консервативный: vendor-owned suffix или
точный FQDN, подтверждённый официальной сетевой/API-документацией. Общие shared
CDN, аналитика и fallback-хосты не включаются до наблюдения конкретного сценария;
точечные официальные asset-хосты самого сервиса допустимы.

Основные источники:

- [OpenAI network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web), [Anthropic API](https://platform.claude.com/docs/en/api/overview), [Gemini API](https://ai.google.dev/api), [GitHub Copilot allowlist](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference), [Microsoft Copilot](https://copilot.microsoft.com/), [Perplexity API](https://docs.perplexity.ai/api-reference/search-post), [xAI enterprise](https://docs.x.ai/build/enterprise), [Midjourney web](https://docs.midjourney.com/hc/en-us/articles/31541509949069-Using-Midjourney-in-Discord);
- [Notion allowlist](https://www.notion.com/help/allowlist-ip), [JetBrains network requirements](https://www.jetbrains.com/help/ide-services-cloud/network-access-requirements.html), [Framer allowlist](https://www.framer.com/help/articles/how-to-whitelist-framer-domains/), [Spotify Web API](https://developer.spotify.com/documentation/web-api/concepts/api-calls), [Twitch API](https://dev.twitch.tv/docs/api/get-started);
- [Xbox GDK network requirements](https://learn.microsoft.com/en-us/gaming/gdk/docs/gdk-dev/console-dev/dev-kits/settings/configure-dev-network), [PlayStation network ports](https://www.playstation.com/en-us/support/error-codes/ps5/nw-102650-4/), [Supercell-owned domains](https://supercell.com/en/our-domains/), [Bungie.net account/API](https://help.bungie.net/hc/en-us/articles/360048716612-Bungie-net-Profile-Account-Creation-Linking-and-Recovery).

`domains/ai.csv`, `work.csv` и `gaming.csv` — удобные группы; рабочий файл
`domains/domains.csv` является их точной конкатенацией. Строки не содержат
комментариев и заголовка, потому что parser sniproxy v2.3.0 ожидает только
`domain.,suffix|fqdn|prefix`.

Игровые web/login endpoints включены, но gameplay, voice и matchmaking часто
используют UDP или другие TCP-порты. Их наличие в списке не означает поддержку
полного игрового трафика. Процесс безопасного расширения описан в
[service discovery](service-discovery.md).
