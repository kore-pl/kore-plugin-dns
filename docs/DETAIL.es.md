# kore-plugin-dns: guía de uso

Plugin de kore para detección DNS, lectura de zonas, consultas reales y escritura de registros (id `dns`): un mismo formato de resultado cubre systemd-resolved, dnsmasq, bind9 y CoreDNS. No incluye servidor DNS, no instala nada, no inicia ni detiene servicios y no escribe configuración del host.

## Instalación y compatibilidad

Instale el tar.gz publicado con el instalador de plugins de kore; el repositorio también se compila por separado (`make build` / `make dist`). Protocolo `kore.plugin.v1`, `requires_kore: >=0.1.0 <0.2.0`, `lifecycle=lazy`, nivel `basic` (faltan dos clases de inyección de fallos exigidas). Las escrituras se ejecutan con el usuario del plugin, sin root_actions; la única acción root es `resolved-flush-caches` (ejecutada como uid=0 por el kernel).

## Métodos

| Método | Entrada | Resultado clave |
| --- | --- | --- |
| `dns.status` | `{engine?}` | Motor principal, versión, sockets y servidores ascendentes; `engine` fuerza auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | Zonas de bloques bind9 y directivas dnsmasq, con `records_count` / `readable` |
| `dns.records` | `{zone}` | Registros A / AAAA / CNAME / MX / TXT / NS, máximo 500 con `truncated` |
| `dns.query` | `{name, type?}` | Consulta real `{answers[], rcode, elapsed_ms, resolver}`; dig → nslookup → resolvedor Go |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | Actualización dinámica RFC 2136 en bind9: instantánea → UPDATE atómico → verificación → reversión; mismo valor idempotente, valor distinto `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | Entradas compatibles 0.4.0: bind9 usa actualización dinámica, dnsmasq escribe un fragmento hosts en el estado del plugin; otros motores `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | Solo tras editar zonas/named.conf a mano: bind9 `rndc reload`, systemd-resolved `resolvectl flush-caches` por canal elevado, dnsmasq devuelve `reload_required=true`. **Los cambios de registros no requieren reload** |
| `dns.config.get/set` | Contrato de configuración | Motor, cuatro rutas de solo lectura y tiempo de espera; guardado atómico 0600 y aplicación inmediata |
| `kore.ping/reload/shutdown` | `{}` | Métodos obligatorios del protocolo |

## Interpretación y límite de seguridad

- `method_capabilities` marca 4 métodos de lectura `system:read` y 7 de escritura `system:admin`; las capacidades son la superficie de autorización.
- Una lista blanca de rutas limita la lectura a archivos de zona; una zona ilegible entrega comandos copiables (`E_NOTFOUND`).
- Las escrituras fallan cerradas: sin journal, sin clave TSIG, clave ilegible o sin nsupdate ⇒ sin escritura; journal en JSONL 0600.
- Zona desconocida → `E_NOTFOUND`; tipos no soportados por dnsmasq → `E_UNSUPPORTED`; nunca fallo silencioso.
- La escritura contra un servidor real no se ha verificado en esta máquina (no hay bind9 con allow-update); la cadena se cubre con pruebas unitarias de host simulado y no se presenta como verificada en campo.

## Compilación y verificación

```bash
make check                 # gofmt + go vet + go test -timeout 200s (incluye race)
go test ./tests/live/...   # lecturas y consultas reales
make build && make dist    # binario estático y tar.gz determinista
```

## Seguridad y contribución

No abra issues públicos para vulnerabilidades; infórmelas según [SECURITY.md](SECURITY.md). Vea [CONTRIBUTING.md](CONTRIBUTING.md). Licencia MIT.
