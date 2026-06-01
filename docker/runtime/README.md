<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Runtime Groundwork

This directory documents the development/runtime Docker scaffolding. It is not a
production deployment definition yet.

The current Compose stack starts infrastructure services by default:

- Postgres, using a TurboVAS development image with pg-gvm runtime dependencies
- Redis
- Mosquitto
- optional `dev-shell` profile for toolchain/container experiments
- optional `gvmd` profile for narrow manager runtime smoke checks

Persistent state is stored outside the repository by default, normally in the
sibling `TurboVAS-runtime` directory. Runtime commands create these host-visible
directories before starting services:

- `postgres/`
- `redis/`
- `mosquitto/`
- `feeds/`
- `run/`
- `logs/`
- `artifacts/`

The initial services bind host ports to `127.0.0.1` only. Source, `build/`, and
`build/prefix` are bind-mounted for fast development feedback instead of forcing
container rebuilds after small source changes.

The Postgres development image currently uses `postgres:16-trixie` so the
container runtime libraries are compatible with `gvm-libs` built on the Ubuntu
24.04 development host.

After `pg-gvm` is built into `build/prefix`, run `just runtime-init` to copy the
extension files into the Postgres container and create or verify the `dba` role,
role grant, and `pg-gvm` extension. The command is idempotent and must not delete
or recreate existing runtime data.

Full `gvmd` daemon startup, `gsad`, `ospd-openvas`, `notus-scanner`, feed
population, certificate generation, scanner registration, and scan execution are
intentionally deferred.
