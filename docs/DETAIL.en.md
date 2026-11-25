# kore-plugin-dns Usage

kore's DNS detection / zone reading / real query / record writing plugin (id `dns`): one result shape covers systemd-resolved, dnsmasq, bind9 and CoreDNS. It does not bundle a DNS server, install anything, start/stop services, or write host configuration.

## Installation and compatibility

Install the released tar.gz with the kore plugin installer; the repository can be built standalone (`make build` / `make dist`). Protocol `kore.plugin.v1`, `requires_kore: >=0.1.0 <0.2.0`, `lifecycle=lazy`, depth level `basic` (two required fault-injection classes are not covered yet). Record writes run as the plugin's own user, without root_actions; the only root action is `resolved-flush-caches` (executed as uid=0 by the kernel).

## Methods

| Method | Input | Key result |
| --- | --- | --- |
| `dns.status` | `{engine?}` | Primary engine, version, listening sockets, upstreams; `engine` can force auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | Zones from bind9 zone blocks and dnsmasq directives, with `records_count` / `readable` |
| `dns.records` | `{zone}` | A / AAAA / CNAME / MX / TXT / NS records, max 500 with `truncated` |
| `dns.query` | `{name, type?}` | Real query result `{answers[], rcode, elapsed_ms, resolver}`; dig → nslookup → Go resolver fallback |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | bind9 RFC 2136 dynamic update: snapshot → atomic UPDATE → authoritative verification → automatic rollback; same value is idempotent, different value gives `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | 0.4.0 compatible write entry points: bind9 uses dynamic update, dnsmasq writes a hosts fragment inside the plugin state directory, other engines return `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | Only after manually editing zone/named.conf: bind9 `rndc reload`, systemd-resolved `resolvectl flush-caches` via the elevated channel, dnsmasq returns `reload_required=true`. **Record changes need no reload** |
| `dns.config.get/set` | Config contract | Engine, four read-only paths, query timeout; atomically stored at 0600 and applied immediately |
| `kore.ping/reload/shutdown` | `{}` | Mandatory protocol methods |

## Reading results and security boundary

- `method_capabilities` marks 4 read methods `system:read` and 7 write methods `system:admin`; capability declarations are the authorization surface.
- A path whitelist confines reads to zone files; unreadable zones yield copyable command hints (`E_NOTFOUND`).
- Write paths fail closed: no journal / no TSIG key / unreadable key / missing nsupdate means no write; journal is stored as 0600 JSONL.
- Unknown zones return `E_NOTFOUND`, record types unsupported by dnsmasq return `E_UNSUPPORTED` — never silent failure.
- Real-server writes have not been verified on this host (no bind9 with allow-update); the write chain is covered by mock-host unit tests and is not claimed as field-verified.

## Build and verification

```bash
make check                 # gofmt + go vet + go test -timeout 200s (including race)
go test ./tests/live/...   # real-host reads and queries
make build && make dist    # static binary and deterministic tar.gz
```

## Security and contributing

Do not open public issues for vulnerabilities; disclose privately per [SECURITY.md](SECURITY.md). See [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.
