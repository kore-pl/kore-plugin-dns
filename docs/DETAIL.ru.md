# kore-plugin-dns — руководство по использованию

Плагин kore для обнаружения DNS, чтения зон, реальных запросов и записи записей (id `dns`): единый формат результатов для systemd-resolved, dnsmasq, bind9 и CoreDNS. Не содержит DNS-сервер, ничего не устанавливает, не запускает и не останавливает службы и не меняет конфигурацию хоста.

## Установка и совместимость

Устанавливайте опубликованный tar.gz через установщик плагинов kore; репозиторий можно собрать отдельно (`make build` / `make dist`). Протокол `kore.plugin.v1`, `requires_kore: >=0.1.0 <0.2.0`, `lifecycle=lazy`, уровень `basic` (два требуемых класса инъекции отказов не покрыты). Запись выполняется пользователем плагина без root_actions; единственное root-действие — `resolved-flush-caches` (выполняется ядром как uid=0).

## Методы

| Метод | Вход | Ключевой результат |
| --- | --- | --- |
| `dns.status` | `{engine?}` | Основной движок, версия, прослушиваемые сокеты, апстримы; `engine` принудительно задаёт auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | Зоны из блоков bind9 и директив dnsmasq с `records_count` / `readable` |
| `dns.records` | `{zone}` | Записи A / AAAA / CNAME / MX / TXT / NS, не более 500 с `truncated` |
| `dns.query` | `{name, type?}` | Реальный запрос `{answers[], rcode, elapsed_ms, resolver}`; dig → nslookup → резолвер Go |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | Динамическое обновление RFC 2136 в bind9: снимок → атомарный UPDATE → проверка → откат; то же значение идемпотентно, другое даёт `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | Совместимые точки записи 0.4.0: bind9 использует динамическое обновление, dnsmasq пишет фрагмент hosts в состояние плагина, остальные движки — `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | Только после ручного изменения зон/named.conf: bind9 `rndc reload`, systemd-resolved `resolvectl flush-caches` через привилегированный канал, dnsmasq возвращает `reload_required=true`. **Изменение записей не требует reload** |
| `dns.config.get/set` | Контракт конфигурации | Движок, четыре доступные только для чтения пути, таймаут запроса; атомарная запись 0600 и немедленное применение |
| `kore.ping/reload/shutdown` | `{}` | Обязательные методы протокола |

## Чтение результатов и граница безопасности

- `method_capabilities` помечает 4 метода чтения как `system:read`, а 7 методов записи — как `system:admin`; объявления возможностей являются поверхностью авторизации.
- Список разрешённых путей ограничивает чтение файлами зон; недоступная зона выдаёт копируемые команды (`E_NOTFOUND`).
- ЗаписьFail-closed: нет журнала, нет ключа TSIG, ключ нечитаем или нет nsupdate ⇒ запись запрещена; журнал — JSONL с режимом 0600.
- Неизвестная зона → `E_NOTFOUND`, неподдерживаемые dnsmasq типы записей → `E_UNSUPPORTED` — никогда не тихий отказ.
- Запись на реальный сервер на этом узле не проверялась (нет bind9 с allow-update); цепочка покрыта модульными тестами с имитацией хоста и не выдаётся за проверенную в бою.

## Сборка и проверка

```bash
make check                 # gofmt + go vet + go test -timeout 200s (включая race)
go test ./tests/live/...   # реальные чтения и запросы на хосте
make build && make dist    # статический бинарник и детерминированный tar.gz
```

## Безопасность и участие

Не открывайте публичные issue по уязвимостям; сообщайте приватно согласно [SECURITY.md](SECURITY.md). Участие: [CONTRIBUTING.md](CONTRIBUTING.md). Лицензия MIT.
