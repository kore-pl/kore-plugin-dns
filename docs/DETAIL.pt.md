# kore-plugin-dns — guia de uso

Plugin do kore para detecção DNS, leitura de zonas, consultas reais e gravação de registros (id `dns`): um mesmo formato de resultado cobre systemd-resolved, dnsmasq, bind9 e CoreDNS. Não inclui servidor DNS, não instala nada, não inicia nem para serviços e não altera a configuração do host.

## Instalação e compatibilidade

Instale o tar.gz publicado com o instalador de plugins do kore; o repositório também pode ser compilado separadamente (`make build` / `make dist`). Protocolo `kore.plugin.v1`, `requires_kore: >=0.1.0 <0.2.0`, `lifecycle=lazy`, nível `basic` (duas classes exigidas de injeção de falhas não cobertas). As gravações executam como o usuário do plugin, sem root_actions; a única ação root é `resolved-flush-caches` (executada como uid=0 pelo kernel).

## Métodos

| Método | Entrada | Resultado principal |
| --- | --- | --- |
| `dns.status` | `{engine?}` | Motor principal, versão, sockets em escuta, upstreams; `engine` força auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | Zonas de blocos bind9 e diretivas dnsmasq, com `records_count` / `readable` |
| `dns.records` | `{zone}` | Registros A / AAAA / CNAME / MX / TXT / NS, máximo 500 com `truncated` |
| `dns.query` | `{name, type?}` | Consulta real `{answers[], rcode, elapsed_ms, resolver}`; dig → nslookup → resolvedor Go |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | Atualização dinâmica RFC 2136 no bind9: snapshot → UPDATE atômico → verificação → reversão; mesmo valor idempotente, valor diferente `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | Entradas compatíveis 0.4.0: bind9 usa atualização dinâmica, dnsmasq grava um fragmento hosts no estado do plugin; demais motores `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | Após editar zonas/named.conf manualmente: bind9 `rndc reload`, systemd-resolved `resolvectl flush-caches` pelo canal elevado, dnsmasq retorna `reload_required=true`. **Mudanças de registros não exigem reload** |
| `dns.config.get/set` | Contrato de configuração | Motor, quatro caminhos somente leitura, timeout de consulta; gravação atômica 0600 e aplicação imediata |
| `kore.ping/reload/shutdown` | `{}` | Métodos obrigatórios do protocolo |

## Interpretação e limite de segurança

- `method_capabilities` marca 4 métodos de leitura `system:read` e 7 de gravação `system:admin`; capacidades são a superfície de autorização.
- Uma lista de permissões restringe a leitura a arquivos de zona; uma zona ilegível fornece comandos copiáveis (`E_NOTFOUND`).
- Gravação fail-closed: sem journal, sem chave TSIG, chave ilegível ou sem nsupdate ⇒ sem gravação; journal em JSONL 0600.
- Zona desconhecida → `E_NOTFOUND`; tipos não suportados pelo dnsmasq → `E_UNSUPPORTED`; nunca falha silenciosa.
- A gravação contra um servidor real não foi verificada neste host (sem bind9 com allow-update); a cadeia é coberta por testes unitários com host simulado e não é apresentada como verificada em campo.

## Compilação e verificação

```bash
make check                 # gofmt + go vet + go test -timeout 200s (inclui race)
go test ./tests/live/...   # leituras e consultas reais no host
make build && make dist    # binário estático e tar.gz determinístico
```

## Segurança e contribuição

Não abra issues públicas para vulnerabilidades; divulgue-as conforme [SECURITY.md](SECURITY.md). Veja [CONTRIBUTING.md](CONTRIBUTING.md). Licença MIT.
