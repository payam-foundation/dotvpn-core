# ADR-021: Egress exits

Status: accepted

## Context

A node dials every destination straight from its own IP. Operators need to pick the exit per destination (WARP for sites that block datacenter IPs, Tor or Psiphon for others), refuse destinations that could expose the node to Iran, and run on v4-only, v6-only and dual-stack hosts.

## Decision

`internal/egress` owns every outbound dial. `Router.Dial(ctx, network, authority)` is its one entry point. `Backend` holds a `Router` instead of a `net.Dialer`. No `node.egress` block means direct dialing behind the SSRF guard, as before.

Evaluation order, first match wins: SSRF guard on IP literals, blocklist (domains, CIDRs, CIDR files), rules, `default` exit. Hostnames are matched before DNS. Proxied exits get the name, so the node does not leak the lookup. Direct dials resolve locally and re-check each resolved IP against the guard and the blocklist. The guard and the blocklist apply to every exit.

Exits:

- `direct`: Happy Eyeballs, with `ip_family: auto | v4 | v6` filtering.
- `socks5`, `http`: sidecars the operator runs (Tor, Psiphon, a corporate proxy). The node dials them and probes the port every 10 s. TCP only.
- `warp`: embedded Cloudflare WARP, an in-process MASQUE (CONNECT-IP) tunnel from the `usque` library feeding a userspace netstack. No root, no kernel TUN, TCP and UDP, v4 and v6. Free account by default, registered on first start and kept in `data_dir/warp-<name>.json` (mode 0600). An optional `license` binds WARP+ or Zero Trust.

Choices made by the maintainers:

- Fail closed. An exit that is down fails the connection. A rule opts into `fallback: direct`, which never applies to a guard or blocklist refusal.
- Country blocking reads CIDR list files (`block.cidr_files: {IR: /etc/dotvpn/geo/ir.txt}`). No GeoIP database, no new dependency, and the lists can be audited and diffed. `install.sh --egress-geo IR` downloads them.
- UDP stays direct unless `udp:` (or a rule's `udp:`) names a warp exit.
- Rules are node-wide. There is no per-user exit.

## Rejected

- Sidecar only for WARP (wireproxy, `warp-cli`): another process to install, supervise and keep in step with the node.
- WireGuard on netstack for WARP: consumer WireGuard endpoints are blocked more often than MASQUE, and the account would need a second key type.
- Per-destination L4 proxy mode of `usque`: Cloudflare answers `CONNECT rejected with status 403` on free accounts for arbitrary targets. Only the full-tunnel mode works, and it was verified on a live server: `warp=on` on `cloudflare.com/cdn-cgi/trace` over v4 and v6, and UDP DNS to `1.1.1.1` and `2606:4700:4700::1111`.
- Fail open: it silently sends traffic from the server IP, the thing an operator who set a rule wants to avoid.
- GeoIP database (MaxMind): a licence, a dependency and an update job, for a list that is a few thousand lines of text.
- Embedded Tor or Psiphon: out of scope; sidecars are enough.

## Consequences

- WARP free-tier terms apply. First start registers an account and so accepts Cloudflare's terms (<https://www.cloudflare.com/application/terms/>). Cloudflare may rate-limit or restrict consumer accounts, and WARP exit IPs are shared.
- `usque` risks: a young project (many open issues), and MASQUE sessions that Cloudflare closes when idle (`H3_NO_ERROR`). The tunnel reconnects every 5 s; the exit reports down until a probe through it succeeds, and dials fail closed in between.
- `usque`'s `connect-ip-go` dependency calls `http3.ParseCapsule`, which `quic-go` v0.64 (needed by `dotvpn-wire`) removed. `third_party/connect-ip-go` is that module with one call moved to `http3.NewCapsuleParser`, wired in with a `replace`. Drop it when `connect-ip-go` is updated upstream.
- `ip_family: auto` makes WARP connect to Cloudflare's v4 endpoint. A v6-only server must set `ip_family: v6`.
- A v6-only server cannot reach v4-only destinations without NAT64, and `64:ff9b::/96` is blocked by the SSRF guard.
- Country lists are read when the node starts. Refresh with `install.sh --upgrade --egress-geo IR`, which restarts it.
- Metrics: `dotvpn_node_egress_exit_up{exit}` and `dotvpn_node_egress_dials_total{exit,result}`.
