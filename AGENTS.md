# dotvpn-core

Server. Module `github.com/payam-foundation/dotvpn-core`, binary `dotvpn-core`. Depends on `dotvpn-wire` only.

Contents: `node` (edge proxy, decoy, egress/SSRF guard), `control`/admin (accounts, tokens, server list), relay enrollment, reverse listener.

## Commands

```sh
go build ./... && go vet ./...
go test -race -count=1 ./...
go build -tags e2e ./cmd/dotvpn-core   # test-only: allows loopback egress for dotvpn-lab. Never release it.
```

`go.mod` has `replace github.com/payam-foundation/dotvpn-wire => ../dotvpn-wire`. CI drops it and tests the pinned wire tag and wire `main`.

## Invariants

- Unauthenticated, invalid, replayed or probing connections get the decoy response, never a silent close or reset; timing stays uniform (ADR-014).
- Admin and metrics listen on loopback or a unix socket only; core refuses anything else at startup.
- Egress blocks RFC1918, loopback, CGNAT, link-local and metadata (`169.254.169.254`) addresses. The `e2e` build tag is the only exception and never ships.
- The rate limiter keys on the socket peer; forwarded headers are ignored.
- Tokens are verified offline against control's public key (ADR-003).

## Shared rules

- Static builds: `CGO_ENABLED=0`, `-trimpath`. Docker base images pinned by digest, distroless, non-root.
- Secrets never go in the repo, unit files, env files or CI. Keys are written 0600/0640.
- Go style: stdlib first, no new dependency for what a few lines do, no placeholder code. Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and the upgrade path.
- Each repo is its own git repo and Go module. Sibling repos live next to this one; do not import across core, relay and client. Anything two of them must agree on goes in `dotvpn-wire`.

## Docs

`docs/adr/`: ADR-006. Operator guide: `README.md` and `deploy/`. Security report: `../dotvpn-lab/docs/REPORT.md`.
