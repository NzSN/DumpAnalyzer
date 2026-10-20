#!/usr/bin/env bash
set -euo pipefail
RUNTIME=/d/Services/dump-ledger-runtime
APP=/d/Services/dump-ledger
export PATH="/d/Services/node24:$PATH"
set -a; source "$RUNTIME/.env"; set +a
cd "$APP"
exec node "$RUNTIME/tmp/p6-ledger-launcher.cjs" "$1"
