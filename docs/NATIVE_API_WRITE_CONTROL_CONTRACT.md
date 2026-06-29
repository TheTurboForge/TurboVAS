<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Native API Write And Control Contract

TurboVAS native API replacement is not limited to reads. Retained write and
control workflows may move to native HTTP/JSON when the slice is explicit,
bounded, and validated.

Every non-GET native operation, request-body operation, or side-effecting
operation must declare these OpenAPI fields before implementation:

- `x-turbovas-exposure`: `internal-only` by default, or `direct-write` only
  after the direct-access auth/exposure posture is deliberately approved for
  that path.
- `x-turbovas-maturity`: `preview-write`, `live-write`, `preview-control`, or
  `live-control`.
- `x-turbovas-replaces`: the inherited product workflow or `none` while the
  contract is still a scaffold.
- `x-turbovas-inherited-still-owns`: the legacy behavior that still owns any
  unreplaced part of the workflow.
- `x-turbovas-operator-identity`: how the write/control operation maps the
  request to an operator principal: `proxied-session-operator`,
  `direct-token-operator`, `service-admin-dev-only`, or
  `not-applicable-preview`.
- `x-turbovas-owner-semantics`: how persistent owner fields or gvmd-style
  current-user semantics are handled: `request-operator-owner`,
  `preserve-existing-owner`, `single-admin-owner`, `no-owner-state`, or
  `not-applicable-preview`.
- `x-turbovas-safety-contract`: currently `write-control-v1`.
- `x-turbovas-side-effect`: one of `metadata-write`, `scanner-control`,
  `feed-control`, `credential-secret-control`, `account-auth-control`,
  `destructive-mutation`, `report-generation`, or `export-generation`.

For each write/control slice, characterize inherited behavior first, then define
authorization, validation and rejection paths, idempotency or rollback semantics,
audit logging, secret redaction, OpenAPI request/response shape, and focused
tests. The rule is not to avoid these paths; the rule is not to half-ass them.

## First Candidate: Scope Metadata And Membership

The preferred first live-write candidate is scope metadata and membership, not
report generation or scanner control. Scope create/modify/delete and target or
host membership edits are metadata writes over gvmd/PostgreSQL state and do not
start scans, touch credentials, mutate feeds, or generate reports by themselves.

Before any scope write route is implemented, the contract must state:

- operator identity and owner semantics for created and modified scopes;
- whether the global scope is immutable, partially editable, or excluded;
- membership invariants for targets, hosts, empty scopes, and duplicate links;
- delete behavior, including any scope-report references that block deletion;
- idempotency and rejection semantics for repeated add/remove operations;
- audit fields that do not include credentials, tokens, or private network
  details.

`generate_scope_report` remains a separate report-generation workflow. It must
not be folded into the first scope metadata-write slice.

Current checks:

- `just native-api-client-contract --status-only --json`
- `just native-tooling-state --status-only --json`

