# kore-plugin-dns — guide d'utilisation

Plugin kore de détection DNS, lecture de zones, requêtes réelles et écriture d'enregistrements (id `dns`) : un même format de résultat couvre systemd-resolved, dnsmasq, bind9 et CoreDNS. Il n'intègre pas de serveur DNS, n'installe rien, ne démarre/arrête aucun service et n'écrit pas la configuration de l'hôte.

## Installation et compatibilité

Installez le tar.gz publié via l'installateur de plugins kore ; le dépôt peut être compilé seul (`make build` / `make dist`). Protocole `kore.plugin.v1`, `requires_kore: >=0.1.0 <0.2.0`, `lifecycle=lazy`, niveau `basic` (deux classes d'injection de fautes exigées manquent). Les écritures s'exécutent avec l'utilisateur du plugin, sans root_actions ; la seule action root est `resolved-flush-caches` (exécutée en uid=0 par le noyau).

## Méthodes

| Méthode | Entrée | Résultat clé |
| --- | --- | --- |
| `dns.status` | `{engine?}` | Moteur principal, version, sockets d'écoute, serveurs amont ; `engine` force auto / systemd-resolved / dnsmasq / bind9 / coredns |
| `dns.zones` | `{}` | Zones issues des blocs bind9 et des directives dnsmasq, avec `records_count` / `readable` |
| `dns.records` | `{zone}` | Enregistrements A / AAAA / CNAME / MX / TXT / NS, 500 max avec `truncated` |
| `dns.query` | `{name, type?}` | Vraie requête `{answers[], rcode, elapsed_ms, resolver}` ; dig → nslookup → résolveur Go |
| `dns.record.add/update/delete` | `{zone,name,type,value,ttl?}` | Mise à jour dynamique RFC 2136 sur bind9 : instantané → UPDATE atomique → vérification → annulation ; même valeur idempotente, valeur différente `E_CONFLICT` |
| `dns.addRecord/updateRecord/deleteRecord` | `{zone,name,type,value,old_value?}` | Entrées compatibles 0.4.0 : bind9 utilise la mise à jour dynamique, dnsmasq écrit un fragment hosts dans l'état du plugin ; autres moteurs `E_UNSUPPORTED` |
| `dns.reload` | `{zone?}` | Uniquement après édition manuelle des zones/named.conf : bind9 `rndc reload`, systemd-resolved `resolvectl flush-caches` via le canal élevé, dnsmasq renvoie `reload_required=true`. **Les changements d'enregistrements ne nécessitent pas de reload** |
| `dns.config.get/set` | Contrat de configuration | Moteur, quatre chemins en lecture seule, délai de requête ; stockage atomique 0600 et application immédiate |
| `kore.ping/reload/shutdown` | `{}` | Méthodes obligatoires du protocole |

## Interprétation et limite de sécurité

- `method_capabilities` marque 4 méthodes de lecture `system:read` et 7 d'écriture `system:admin` ; les capacités sont la surface d'autorisation.
- Une liste blanche de chemins limite la lecture aux fichiers de zone ; une zone illisible fournit des commandes copiables (`E_NOTFOUND`).
- Les écritures échouent fermées : pas de journal, pas de clé TSIG, clé illisible ou nsupdate manquant ⇒ aucune écriture ; journal en JSONL 0600.
- Zone inconnue → `E_NOTFOUND` ; types non pris en charge par dnsmasq → `E_UNSUPPORTED` ; jamais d'échec silencieux.
- L'écriture contre un serveur réel n'a pas été vérifiée sur cette machine (pas de bind9 avec allow-update) ; la chaîne est couverte par des tests unitaires avec hôte simulé et n'est pas présentée comme vérifiée sur le terrain.

## Compilation et vérification

```bash
make check                 # gofmt + go vet + go test -timeout 200s (y compris race)
go test ./tests/live/...   # lectures et requêtes réelles
make build && make dist    # binaire statique et tar.gz déterministe
```

## Sécurité et contribution

N'ouvrez pas d'issue publique pour une vulnérabilité ; signalez-la selon [SECURITY.md](SECURITY.md). Voir [CONTRIBUTING.md](CONTRIBUTING.md). Licence MIT.
