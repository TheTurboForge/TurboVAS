<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Building TurboVAS

TurboVAS currently has a local inherited-stack build baseline for:

- C services: `gvm-libs`, `openvas-smb`, `openvas-scanner`, `pg-gvm`, `gvmd`, `gsad`
- Web UI: `gsa`
- Python components: `python-gvm`, `gvm-tools`, `greenbone-feed-sync`, `ospd-openvas`, `notus-scanner`

Build output, local install artifacts, Python virtual environments, and component dependency directories are kept under ignored paths. C components install into `build/prefix` when downstream components need their pkg-config metadata and headers.

## Commands

Check dependency readiness:

```sh
just deps
just deps gvmd
just deps gsa
```

Build one supported component:

```sh
just build gvmd
just build gsad
just build pg-gvm
just build gsa
just build python-gvm
```

Build grouped baselines:

```sh
just build-core-c
just build-c-services
just build-ui
just build-python
just build-baseline
```

Machine-readable output is available through `tools/turbovasctl`, for example:

```sh
tools/turbovasctl deps --json
tools/turbovasctl build-baseline --json
```

`tools/forkctl` remains as a temporary compatibility wrapper during the command
rename.

## Notes

The server baseline uses the Ubuntu `libcurl4-gnutls-dev` package because the scanner build expects the GnuTLS curl variant.

The scanner build currently passes `-isystem /usr/include/mit-krb5` through
`turbovasctl` because Ubuntu's `mit-krb5-gssapi` pkg-config metadata exposes the
GSSAPI header path there. This keeps the Phase 2 baseline reproducible without
modifying imported source code.

The web UI baseline uses Node.js 22 with npm 11 from an official Node.js binary installation on the development server. The NodeSource apt repository was not used for the final install because its dry-run transaction would have removed unrelated distro Node tooling.

The Python baseline uses `uv` with per-component virtual environments under `build/venvs`.

## Runtime Groundwork

The current Docker runtime baseline starts infrastructure services and an
experimental inherited application profile:

```sh
just runtime-plan
just up
just runtime-certs-init
just runtime-init
just runtime-manager-init
just runtime-scanner-redis-init
just runtime-gmp-smoke
just runtime-scanner-register
just feed-state
just feed-cache-sync
just feed-copy-to-runtime
just runtime-status
just runtime-smoke
just runtime-app-up
just runtime-app-smoke
just runtime-app-down
just down
```

Runtime state is host-visible and persistent under the sibling
`TurboVAS-runtime` directory by default when commands are run through
`tools/turbovasctl`. `runtime-certs-init`, `runtime-init`,
`runtime-manager-init`, scanner Redis/config initialization, scanner
registration, and feed copy commands are designed to be idempotent and must not
delete or recreate unrelated runtime data.

The current app profile can start `gvmd`, `ospd-openvas`, and `gsad` for first
service-health checks. Feed downloads use a persistent local Community Feed
cache under `TurboVAS-runtime/feed-cache/`, then runtime services consume
physical copies under `TurboVAS-runtime/feeds/`. Notus daemon bring-up, scan
execution, and production packaging remain deferred.
