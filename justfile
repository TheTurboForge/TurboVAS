set shell := ["bash", "-eo", "pipefail", "-c"]

forkctl *args:
    @set -- {{args}}; if [ "${1:-}" = "--" ]; then shift; fi; tools/forkctl "$@"

status:
    @tools/forkctl status

inventory:
    @tools/forkctl inventory

doctor:
    @tools/forkctl doctor

license-report:
    @tools/forkctl license-report
