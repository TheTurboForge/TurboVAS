# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later

set shell := ["bash", "-eo", "pipefail", "-c"]

turbovasctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/turbovasctl "$@"

forkctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/forkctl "$@"

status:
    @tools/turbovasctl status

inventory:
    @tools/turbovasctl inventory

doctor:
    @tools/turbovasctl doctor

license-report:
    @tools/turbovasctl license-report

deps component="":
    @if [ -n "{{component}}" ]; then tools/turbovasctl deps "{{component}}"; else tools/turbovasctl deps; fi

configure component:
    @tools/turbovasctl configure "{{component}}"

build component:
    @tools/turbovasctl build "{{component}}"

build-core-c:
    @tools/turbovasctl build-core-c

build-c-services:
    @tools/turbovasctl build-c-services

build-ui:
    @tools/turbovasctl build-ui

build-python:
    @tools/turbovasctl build-python

build-baseline:
    @tools/turbovasctl build-baseline

runtime-plan:
    @tools/turbovasctl runtime-plan

up:
    @tools/turbovasctl up

down:
    @tools/turbovasctl down

logs service="":
    @if [ -n "{{service}}" ]; then tools/turbovasctl logs "{{service}}"; else tools/turbovasctl logs; fi

runtime-init:
    @tools/turbovasctl runtime-init

runtime-status:
    @tools/turbovasctl runtime-status

runtime-smoke:
    @tools/turbovasctl runtime-smoke

gvmd-smoke:
    @tools/turbovasctl gvmd-smoke
