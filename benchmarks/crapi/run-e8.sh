#!/usr/bin/env bash
# E8: run the role-aware scanner against OWASP crAPI. LOCAL ONLY.
# Prereqds: git clone https://github.com/OWASP/crAPI benchmarks/crapi/crAPI
#           (cd benchmarks/crapi/crAPI/deploy/docker && sed -i 's/TLS_ENABLED=true/TLS_ENABLED=false/' .env && docker compose up -d)
# Then create the accounts and scan:
set -euo pipefail
B="${1:-http://localhost:8888}"
P="Bac#Test2026"
curl -fsS -XPOST "$B/identity/api/auth/signup" -H 'content-type: application/json' -d "{\"name\":\"Alice Test\",\"email\":\"alice.bac@example.test\",\"number\":\"4000000001\",\"password\":\"$P\"}" >/dev/null || true
curl -fsS -XPOST "$B/identity/api/auth/signup" -H 'content-type: application/json' -d "{\"name\":\"Bob Test\",\"email\":\"bob.bac@example.test\",\"number\":\"4000000002\",\"password\":\"$P\"}" >/dev/null || true
curl -fsS -XPOST "$B/workshop/api/mechanic/signup" -H 'content-type: application/json' -d "{\"name\":\"Mech Test\",\"email\":\"mech.bac@example.test\",\"number\":\"4000000003\",\"password\":\"$P\",\"mechanic_code\":\"TRAC_JHt2\"}" >/dev/null || true
# NOTE: crAPI has IP-level login rate limiting; avoid repeated login loops or it locks out.
node cli-tool/src/cli.js scan \
  --spec benchmarks/crapi/crAPI/openapi-spec/crapi-openapi-spec.json \
  --config benchmarks/crapi/crapi.config.yaml \
  --target "$B" --out evaluation/results/2026-11-21-crapi-e8/crapi-findings.json --fail-on none
