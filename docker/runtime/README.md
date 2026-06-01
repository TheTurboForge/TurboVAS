<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Runtime Groundwork

This directory documents the development/runtime Docker scaffolding. It is not a
production deployment definition yet.

The default Compose stack starts infrastructure services:

- Postgres, using a TurboVAS development image with pg-gvm runtime dependencies
- Redis
- Mosquitto
- optional `dev-shell` profile for toolchain/container experiments

The experimental `app` profile adds inherited application services:

- `gvmd`, using the persistent Postgres database and a runtime Unix socket
- `ospd-openvas`, wired to the built OpenVAS scanner binary and runtime OSP socket path
- `gsad`, exposed on `127.0.0.1:19392` for local HTTPS/API smoke checks

Persistent state is stored outside the repository by default, normally in the
sibling `TurboVAS-runtime` directory. Runtime commands create host-visible
storage for Postgres, Redis, Mosquitto, feeds, run sockets, logs, artifacts,
certificates, secrets, and service state.

The services bind host ports to `127.0.0.1` only. Source, `build/`, and
`build/prefix` are bind-mounted for fast development feedback instead of forcing
container rebuilds after small source changes. App containers also mount the
checkout at `/home/turboforge/Projects/TurboVAS` because the current CMake build
baseline embeds inherited development paths under that location.

## Commands

Use the root `justfile` command surface:

- `just runtime-plan`
- `just up`
- `just runtime-certs-init`
- `just runtime-init`
- `just runtime-manager-init`
- `just runtime-status`
- `just runtime-smoke`
- `just runtime-app-up`
- `just runtime-app-smoke`
- `just runtime-app-down`
- `just down`

`runtime-certs-init` uses inherited `gvm-manage-certs` with persistent runtime
certificate directories and does not rotate existing certificates.

`runtime-init` copies `pg-gvm` extension files into the active Postgres container
and creates or verifies the `dba` role, role grant, and `pg-gvm` extension. It
must not delete or recreate existing runtime data.

`runtime-manager-init` runs the `gvmd` database migration, creates or verifies a
local development admin user, stores the generated development password under
the runtime `secrets/` directory, and sets the feed import owner when possible.

## Current App Runtime Status

The current app profile can start `gvmd` and `gsad` far enough for service-health
smoke checks:

- `gvmd` starts and creates `/runtime/run/gvmd/gvmd.sock`.
- `gsad` starts in API-only mode and responds on loopback HTTPS.
- `ospd-openvas` is wired to the built `openvas` binary but currently exits
  before creating its OSP socket because scanner KB Redis connectivity is not
  configured for the container topology yet.

Full feed population, scanner registration finalization, Notus bring-up, OSP
socket readiness, authenticated GMP client checks, scan execution, and production
packaging are intentionally deferred.
