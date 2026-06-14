<!-- SPDX-FileCopyrightText: 2026 TurboVAS contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# TurboVAS Database Gravity

TurboVAS reporting and analytics depend on deterministic, queryable state.
Product-critical data should move toward gvmd/PostgreSQL unless there is a clear
reason to keep it as runtime state, cache, log, or artifact.

## Rule Of Thumb

Put data in gvmd/PostgreSQL when it is part of the product contract:

- operator-managed objects such as targets, tasks, credentials, schedules,
  filters, scopes, and scope membership;
- raw reports, results, hosts, ports, applications, operating systems, CVEs,
  TLS certificates, and vulnerability evidence;
- generated scope reports and their source-report provenance;
- snapshot metrics that must remain stable after generation;
- future inventory/evidence/applicability records that operators query,
  compare, export, or audit.

Keep data outside PostgreSQL when it is not product state:

- feed content and feed caches, because feed terms and scanner expectations are
  separate from manager-owned product records;
- runtime logs, because they are operational diagnostics;
- generated command artifacts, because they preserve execution evidence for
  humans and automation but should not become hidden product truth;
- temporary sockets, pids, certificates, local secrets, and service state;
- build outputs, staged static UI bundles, and local virtual environments.

## Current Classifications

`runtime-data-state --json` classifies known runtime paths as:

- `system_of_record`: gvmd/PostgreSQL state;
- `artifact`: diagnostic/report/smoke outputs under `TurboVAS-runtime/artifacts`;
- `feed_content`: canonical feed cache and runtime feed copy;
- `log`: Docker/runtime logs;
- `temporary_runtime_state`: service state such as keyrings, sockets, and
  runtime-local files.

The command also checks current core tables, scope tables, metric snapshot
tables, row counts where available, and absence of removed inherited feature
tables.

## Design Guidance

When adding a workflow, ask these questions before choosing storage:

1. Does an operator need to filter, sort, compare, export, audit, or link to it?
2. Would losing the data change a report, metric, finding, or decision later?
3. Does the data need schema migration, retention, deletion protection, or
   provenance?
4. Is the data merely evidence that a command ran, a runtime log, or a cache
   that can be regenerated?

If the answer to the first three questions is yes, the data probably belongs in
gvmd/PostgreSQL. If the answer is mostly the fourth question, keep it outside
the database and make the classification explicit.

## Near-Term Use

Use `runtime-data-state --json` before major reporting, metrics, scope, or
inventory work to identify product data that is still outside the database.
Do not move data merely for tidiness; move it when the product needs durable
query semantics, provenance, retention, or shared API access.
