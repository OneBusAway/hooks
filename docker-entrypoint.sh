#!/bin/sh
# First-boot bootstrap for the hooks server image.
#
# When /data has neither hooks.yaml nor hooks.db (a freshly-mounted persistent
# volume), run `hooks init --dir /data` so the server can start. Without this,
# Render Blueprint deploys crash-loop on the very first boot — the volume is
# empty, the server can't read hooks.yaml, and Render's Shell tab is gated on
# a running instance, so the documented recovery path is unreachable.
#
# The auto-init prints a one-time admin token and bootstrap signup URL to
# stdout. On Render those land in the service log (private to your team).
# Treat both as secrets.
#
# Subcommands (init/invite/prune/verify/help) bypass the bootstrap — they're
# already past the "fresh volume" case or want explicit control.

set -e

case "${1:-}" in
    init|invite|prune|verify|help|-h|--help)
        ;;
    *)
        if [ ! -f /data/hooks.yaml ] && [ ! -f /data/hooks.db ]; then
            /usr/local/bin/hooks init --dir /data
        fi
        ;;
esac

exec /usr/local/bin/hooks "$@"
