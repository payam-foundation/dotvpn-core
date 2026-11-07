# ADR-020: Certificate selection for unknown SNI and extra domains

Status: proposed

## Context

Hetzner test (see `dotvpn-lab/docs/hetzner-test-report.md`): one core host answers for several names, some DNS-only and some behind Cloudflare. CertMagic's default behaviour broke two of them:

1. Cloudflare in front, a name the origin has no certificate for. Cloudflare forwards the visitor's hostname as SNI. CertMagic found no certificate for that name and aborted the handshake with TLS alert 80 (`internal_error`). Cloudflare answered 525/526 and the carrier never connected.
2. A second DNS zone for the same node (`dotc.dotsquad.ir` next to `dotc.davod.uk`). `node.domain` takes one name, so the second name had no certificate and failed the same way.

An alert is also a probe tell: a scanner or a censor's active prober that connects by IP, or with a made-up SNI, sees a TLS stack that behaves unlike the decoy site. ADR-014 requires unauthenticated and probing connections to get the decoy, not a reset or alert.

## Decision

1. `node.alt_domains` lists extra names. They are managed (ACME issued and renewed) next to `node.domain`, each with its own certificate. A name in `alt_domains` is served its own certificate.
2. CertMagic's `DefaultServerName` (no SNI) and `FallbackServerName` (SNI that matches nothing) are both set to `node.domain`. Any other ClientHello gets the primary certificate and then follows the normal path: the decoy, or a 407 for a bad token.
3. `FallbackServerName` is marked experimental upstream. `TestUnknownSNIGetsNodeCertificate` pins the behaviour, so a CertMagic bump that changes it fails CI rather than production.

## Scenarios

| Cloudflare mode / setup | Origin sees | Before | After |
| --- | --- | --- | --- |
| DNS only (grey cloud), own name | SNI = the name | works if the name is `domain` or in `alt_domains` | same |
| DNS only, name not configured | SNI = unknown | alert 80 | primary certificate, then decoy. The client still fails its own certificate check against that name, which is correct: it is not our name |
| Proxied, **Full** | Cloudflare connects with the visitor's host as SNI; the origin certificate is not validated | alert 80 when the proxied name is not in the certificate set | primary certificate is accepted by Cloudflare, traffic flows |
| Proxied, **Full (strict)** | same SNI, but the certificate must be valid and cover the requested hostname | 526 | works only if the proxied name is `domain` or in `alt_domains` (each gets its own certificate). Fallback does not help here: the fallback certificate does not cover the proxied name, so Cloudflare answers 526 |
| Proxied, **Flexible** | Cloudflare speaks plain HTTP to port 80 | not served. The node listens for TLS on 443 only, so nothing answers and the carrier fails | unchanged. Flexible cannot carry a TLS tunnel carrier. Use Full or Full (strict) |
| Proxied, Origin Rule with an SNI override (Enterprise) | the override value | works if the override is in the set | same |
| Proxied, hostname in no certificate set, Full (strict) | n/a | 526 | 526. Add the name to `alt_domains` |

The measured setup uses Full. The six names answered 200 from both the Mac and the Iran host. The proxied names (`cdotc.davod.uk`, `cdotir.davod.uk`) present Cloudflare's edge certificate to clients. The origin leg is Cloudflare to the node, where the fallback applies.

ACME needs each name to resolve to this host for HTTP-01 or TLS-ALPN-01. A proxied name is validated through Cloudflare, which works while it passes port 443 and 80 through.

Evidence: the "Before" and "After" for unknown SNI and for missing SNI are asserted by `TestUnknownSNIGetsNodeCertificate` (the baseline fails, the fix passes). The Full row was measured end to end on the Hetzner host. The Full (strict), Flexible and Origin Rule rows follow from Cloudflare's documented behaviour ([encryption modes](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/), [Origin Rules](https://developers.cloudflare.com/rules/origin-rules/features/)) and were not run against a strict zone. Re-test with the zone set to Full (strict) before relying on them.

## Rejected

- Serve one self-signed certificate for unknown SNI. A censor reading the certificate learns it is not the decoy's.
- Wildcard certificate through DNS-01. Needs DNS provider credentials on the node. A single-VPS install should not hold them.
- `OnDemand` TLS (issue on first request for any name). Lets anyone burn the Let's Encrypt rate limit by sending SNI values, and ties up validation.
- `GetCertificate` callback of our own. Duplicates CertMagic's cache and renewal logic for the sake of one lookup.
- Per-name listeners. A node serves every carrier on one TLS port by design.

## Consequences

- No new dependency. The change is two fields in `tls.go`, one list in config.
- Operators running Full (strict) must list every proxied name in `alt_domains` or set `domain` to it. The first name is the fallback.
- If CertMagic removes `FallbackServerName`, the test fails and this ADR is revisited.
