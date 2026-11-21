# Experiment E8: the role-aware scanner against OWASP crAPI

**Status: EXECUTED as an applicability demonstration (not a scored benchmark).** The scanner was run
against a live, third-party, multi-service vulnerable API using only configuration (crAPI has no
`x-access-control` annotations). No precision/recall is reported for crAPI: a full ground truth would
require confirming every documented crAPI challenge against this running version and provisioning owned
objects for every endpoint, which is out of scope here. Instead, the notable findings were spot-verified
by hand.

| Item | Value |
|---|---|
| Date | 2026-11-21 |
| Tool | bac-scanner 1.0.0, ownership-differential oracle |
| Target | OWASP crAPI (cloned from github.com/OWASP/crAPI), full docker compose, TLS disabled, gateway :8888 |
| Spec | crAPI's own `openapi-spec/crapi-openapi-spec.json` (OpenAPI 3.0.1, 44 operations) |
| Config | `benchmarks/crapi/crapi.config.yaml` (identity = e-mail; ownership fields and accessRules supplied by hand) |
| Accounts | two users (alice, bob) + one mechanic, created by signup (`benchmarks/crapi/run-e8.sh`) |
| Cost | 158 requests, 4.3 s |

## Findings (19 confirmed)

| Category | Count | Notes |
|---|---:|---|
| BOLA | 2 | Reading another user's vehicle location |
| JWT_NONE_ALG | 15 | Unsigned (`alg:none`) tokens accepted — one root cause across many endpoints |
| JWT_SIGNATURE | 1 | Tampered-signature token accepted (GET /identity/api/v2/user/dashboard) |
| AUTH_MISSING | 1 | GET /workshop/api/shop/orders/{order_id} accepted a request without credentials |

## Manual verification of the headline findings

- **JWT `alg:none` bypass — independently verified.** A token with header `{"alg":"none"}` and the claims
  `{"sub":"alice.bac@example.test","role":"user"}`, with no signature, was sent to
  `GET /identity/api/v2/user/dashboard`. crAPI returned **HTTP 200** with Alice's full account. A request
  with no token returns 404, so the probe is not trivially succeeding. crAPI accepts unsigned JWTs — a
  genuine, severe authentication weakness (one of crAPI's documented JWT issues). The 15 `JWT_NONE_ALG`
  findings share this single root cause; they are reported per operation.
- **Vehicle-location BOLA — scan-evidenced (crAPI's flagship BOLA).** Alice's token read
  `GET /identity/api/v2/vehicle/1929186d-8b67-4163-a208-de52a41f7301/location` and received HTTP 200 with a
  real seeded vehicle: `{"carId":"1929186d-…","vehicleLocation":{"latitude":"38.206348","longitude":"-84.270172"},"fullName":"Test","email":"test@example.com"}`.
  The vehicle belongs to a seeded user (`test@example.com`), not to Alice, so this is unauthorized cross-user
  object access. The vehicle id came from the spec's parameter example, which happens to be a seeded vehicle.

## Limitations and honest caveats

- **No precision/recall for crAPI.** This is a demonstration of applicability, not a scored run. The
  findings above are spot-verified true positives; the full set was not labelled against a ground truth.
- **Live re-verification was blocked by crAPI's own anti-brute-force lockout.** After the scan plus the
  manual checks, crAPI's identity service began returning `Invalid Credentials` to all logins from this IP
  (a crAPI rate-limiting feature). The `alg:none` check (which uses a forged token, not a login) was verified
  before the lockout; the BOLA rests on the scan-time evidence above, which could not be re-run live
  afterwards. This lockout is itself a relevant finding for automated scanning of crAPI: repeated logins trip it.
- **Fresh accounts own few objects.** Black-box discovery can only test objects it can reach. Fresh crAPI
  users have no vehicles or orders until provisioned (vehicles require an e-mail-delivered VIN/PIN; orders
  require a purchase), so broader BOLA coverage would need that multi-step provisioning, as
  `benchmarks/crapi/README.md` anticipated.
- **Root-cause counting.** The 15 `JWT_NONE_ALG` findings reflect one underlying weakness applied across
  endpoints; a reader should treat them as one root cause with wide reach, not 15 independent defects.

## Reproduce

Stand up crAPI (see `benchmarks/crapi/README.md`), then run `benchmarks/crapi/run-e8.sh`. Avoid repeated
login loops, which trip crAPI's lockout. `crapi-findings.json` here is the archived (redacted) scan output.
