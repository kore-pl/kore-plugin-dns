# kore-plugin-dns — Anwendungshandbuch

kore-Plugin für DNS-Erkennung, Zonenlesen, echte Abfragen und Eintragsschreiben (id `dns`): ein einheitliches Ergebnisformat für systemd-resolved, dnsmasq, bind9 und CoreDNS. Es enthält keinen DNS-Server, installiert nichts, startet/stoppt keine Dienste und schreibt keine Host-Konfiguration.

## Installation und Kompatibilität

Installieren Sie das veröffentlichte tar.gz mit dem kore-Plugin-Installer; das Repository kann einzeln gebaut werden (`make build` / `make dist`). Protokoll `kore.plugin.v1`, `requires_kore: >=0.1.0 <0.2.0`, `lifecycle=lazy`, Tiefe `basic` (zwei geforderte Fehlerinjektionsklassen fehlen). Schreibvorgänge laufen als Plugin-Benutzer ohne root_actions; die einzige Root-Aktion ist `resolved-flush-caches` (vom Kernel als uid=0 ausgeführt).

## Methoden

| Methode | Eingabe | Wichtigstes Ergebnis |
| --- | --- | --- |
| `dns.status` | `{engine?}` | Haupt-Engine, Version, lauschende Sockets, Upstreams; `engine` erzwingt auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | Zonen aus bind9-Zonenblöcken und dnsmasq-Direktiven, mit `records_count` / `readable` |
| `dns.records` | `{zone}` | Einträge A / AAAA / CNAME / MX / TXT / NS, maximal 500 mit `truncated` |
| `dns.query` | `{name, type?}` | Echte Abfrage `{answers[], rcode, elapsed_ms, resolver}` ; dig → nslookup → Go-Resolver |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | bind9 RFC 2136 Dynamic Update: Snapshot → atomares UPDATE → Verifikation → Rückgängigmachen; gleicher Wert idempotent, anderer Wert `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | Kompatible Schreibzugänge 0.4.0: bind9 nutzt Dynamic Update, dnsmasq schreibt ein hosts-Fragment im Plugin-Statusverzeichnis, andere Engines `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | Nur nach manueller Änderung von Zonen/named.conf: bind9 `rndc reload`, systemd-resolved `resolvectl flush-caches` über den elevierten Kanal, dnsmasq liefert `reload_required=true`. **Eintragsänderungen brauchen kein reload** |
| `dns.config.get/set` | Konfigurationsvertrag | Engine, vier schreibgeschützte Pfade, Abfrage-Timeout; atomar mit 0600 gespeichert und sofort wirksam |
| `kore.ping/reload/shutdown` | `{}` | Obligatorische Protokollmethoden |

## Ergebnisse und Sicherheitsgrenze

- `method_capabilities` markiert 4 Lesemethoden als `system:read` und 7 Schreibmethoden als `system:admin`; Capabilities sind die Autorisierungsfläche.
- Eine Pfad-Whitelist beschränkt Lesevorgänge auf Zonendateien; eine nicht lesbare Zone liefert kopierbare Befehle (`E_NOTFOUND`).
- Schreibvorgänge fail closed: kein Journal, kein TSIG-Schlüssel, unlesbarer Schlüssel oder fehlendes nsupdate ⇒ kein Schreiben; Journal als 0600-JSONL.
- Unbekannte Zone → `E_NOTFOUND`, von dnsmasq nicht unterstützte Eintragstypen → `E_UNSUPPORTED` — kein stilles Scheitern.
- Das Schreiben gegen einen echten Server wurde auf diesem Host nicht geprüft (kein bind9 mit allow-update); die Kette ist durch Unit-Tests mit simuliertem Host abgedeckt und wird nicht als feldverifiziert ausgegeben.

## Bauen und prüfen

```bash
make check                 # gofmt + go vet + go test -timeout 200s (inkl. Race-Gate)
go test ./tests/live/...   # echte Host-Lesevorgänge und Abfragen
make build && make dist    # statische Binary und deterministisches tar.gz
```

## Sicherheit und Mitwirkung

Melden Sie Schwachstellen nicht in öffentlichen Issues, sondern gemäß [SECURITY.md](SECURITY.md). Beiträge: [CONTRIBUTING.md](CONTRIBUTING.md). MIT-Lizenz.
