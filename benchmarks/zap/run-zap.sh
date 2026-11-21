#!/usr/bin/env bash
# Runs the OWASP ZAP API scan (OpenAPI import + active scan) against the LOCAL benchmark API,
# authenticated as one regular user, and converts the result into the findings format.
#
# Usage: benchmarks/zap/run-zap.sh [target=http://localhost:3000] [out-dir=evaluation/results/tmp/zap] [username=alice] [password=Alice#2026]
# Optional environment (defaults fit test-api; see benchmarks/vampi/README.md for VAmPI):
#   SPEC=test-api/openapi.yaml  SPEC_SERVER=http://localhost:3000  LOGIN_PATH=/api/auth/login
#   TOKEN_FIELD=token  RESET_PATH=/__benchmark/reset
# Requires: Docker, a running benchmark (docker compose up -d), Node.js.
set -euo pipefail

TARGET="${1:-http://localhost:3000}"
OUT="${2:-evaluation/results/tmp/zap}"
USERNAME="${3:-alice}"
PASSWORD="${4:-Alice#2026}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
SPEC="${SPEC:-test-api/openapi.yaml}"
SPEC_SERVER="${SPEC_SERVER:-http://localhost:3000}"
LOGIN_PATH="${LOGIN_PATH:-/api/auth/login}"
TOKEN_FIELD="${TOKEN_FIELD:-token}"
RESET_PATH="${RESET_PATH:-/__benchmark/reset}"

case "$TARGET" in
  http://localhost*|http://127.0.0.1*) ;;
  *) echo "Refusing to scan non-local target: $TARGET" >&2; exit 2 ;;
esac

mkdir -p "$OUT"
chmod 777 "$OUT"
# Point the spec's server URL at the target (the spec defaults to http://localhost:3000).
sed "s#url: $SPEC_SERVER#url: $TARGET#" "$SPEC" > "$OUT/openapi.yaml"

# Reset the benchmark so every run starts from the same seed.
curl -fsS -X "${RESET_METHOD:-POST}" "$TARGET$RESET_PATH" >/dev/null || echo "warning: reset endpoint unavailable" >&2

TOKEN=$(curl -fsS -X POST "$TARGET$LOGIN_PATH" -H 'content-type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" | TOKEN_FIELD="$TOKEN_FIELD" node -pe 'JSON.parse(require("fs").readFileSync(0))[process.env.TOKEN_FIELD]')
[ -n "$TOKEN" ] && [ "$TOKEN" != "undefined" ] || { echo "login failed" >&2; exit 1; }

# ZAP "replacer" rule adds the Authorization header to every request.
ZAP_OPTS="-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true \
-config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization \
-config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=Bearer\ $TOKEN"

START=$(date +%s%3N)
set +e
docker run --rm --network host -v "$(pwd)/$OUT:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi \
  -J zap-report.json -r zap-report.html -I -z "$ZAP_OPTS" > "$OUT/zap-console.log" 2>&1
STATUS=$?
set -e
END=$(date +%s%3N)
echo "ZAP exit status: $STATUS (see $OUT/zap-console.log); duration $((END - START)) ms"
[ -f "$OUT/zap-report.json" ] || { echo "ZAP produced no JSON report" >&2; exit 1; }

node evaluation/adapters/zap.js --zap "$OUT/zap-report.json" --spec "$SPEC" --out "$OUT/zap-findings.json" --duration-ms "$((END - START))"

# Leave the benchmark clean for the next experiment.
curl -fsS -X "${RESET_METHOD:-POST}" "$TARGET$RESET_PATH" >/dev/null || true
