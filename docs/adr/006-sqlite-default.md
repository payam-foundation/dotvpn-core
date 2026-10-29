# ADR-006: SQLite default, Postgres behind a store seam

Status: accepted

## Context

Control state in one file unless you need more.

## Decision

A single-instance control plane on pure-Go SQLite (`modernc.org/sqlite`) keeps install trivial and the binary CGO-free. A `postgres://` database URL selects the second adapter for operators who want it.

## Rejected

Postgres only: an install-time dependency most single-VPS operators do not want.
