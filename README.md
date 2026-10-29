# Wildbox Robots Scanner

> Public experimental source: see [PUBLICATION.md](PUBLICATION.md) for actual checks, known defects, restored modules and operational limits. Earlier audit decisions are historical.

Исследовательский Python-скрипт для инвентаризации поддоменов и проверки доступности `robots.txt`.

## Статус аудита

Репозиторий лучше держать private и не использовать в резюме как публичный проект.

Причины:

- скрипт сканирует поддомены конкретного домена;
- даже при легитимной внутренней задаче публичный репозиторий может выглядеть как reconnaissance tooling;
- перед публикацией нужен legal/ToS review и замена конкретного домена на нейтральный demo target.

## Что делает

- собирает поддомены через `crt.sh`;
- умеет дополнительно использовать `bufferover.run` и `RapidDNS`;
- поддерживает опциональный поиск через Censys, если ключи заданы в переменных окружения;
- отправляет `HEAD`, затем `GET` к `/robots.txt`;
- сохраняет технический лог проверки.

## Конфигурация

Censys credentials не должны храниться в репозитории:

```bash
export CENSYS_API_ID=<id>
export CENSYS_API_SECRET=<secret>
python jll.py
```

В проверенном текущем коде Censys credentials читаются из окружения через `os.getenv`.

## Запуск

```bash
pip install -U aiohttp
python jll.py
```

## Перед возможной публикацией

1. Заменить конкретный домен на аргумент CLI и demo value вроде `example.com`.
2. Добавить rate-limit, user-agent и explicit authorization notice.
3. Проверить историю Gitleaks/TruffleHog.
4. Удалить логи и артефакты запусков.

## License

Private до legal/security review.
