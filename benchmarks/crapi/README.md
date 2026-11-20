# OWASP crAPI benchmark

**Status: setup documented; no experiment has been executed on crAPI yet.**

[OWASP crAPI](https://github.com/OWASP/crAPI) ("completely ridiculous API") is a multi-service,
intentionally vulnerable application: identity, community and workshop services, plus a web front end,
PostgreSQL, MongoDB and MailHog. It is considerably heavier than VAmPI. It is also harder to evaluate
automatically, because several of its access-control flaws need multi-step state such as a vehicle that is
verified by e-mail.

## Start (local only)

```bash
git clone --depth 1 https://github.com/OWASP/crAPI.git benchmarks/crapi/crAPI
```

```bash
cd benchmarks/crapi/crAPI/deploy/docker && LISTEN_IP=127.0.0.1 docker compose -f docker-compose.yml --compatibility up -d
```

The web UI listens on `http://127.0.0.1:8888` and MailHog on `http://127.0.0.1:8025`. The clone is git-ignored.
Follow the crAPI README for the current version, because the project changes its deployment files between releases.

## Test accounts (manual preparation)

crAPI has no fixed seed users for the vehicle workflow. Prepare at least two users:

1. `POST /identity/api/auth/signup` with name, e-mail, phone number and password, once per user (for example `user-a@example.test`, `user-b@example.test`).
2. `POST /identity/api/auth/login` returns `token` (JWT, `sub` = e-mail).
3. Add a vehicle per user: the VIN and PIN arrive by e-mail in MailHog, then `POST /identity/api/v2/vehicle/add_vehicle`.
4. The vehicle IDs (UUIDs) of other users become visible through community posts (`GET /community/api/v2/community/posts/recent`).

## Configuration notes

* **Identity = e-mail address.** Ownership in responses is expressed as `email` / `fullName` (e.g.
  `GET /identity/api/v2/vehicle/{vehicleId}/location`), not as numeric owner IDs.
* Path parameters are UUIDs (`vehicleId`) or report and order IDs. A tool must be configured with
  where to obtain each user's own identifiers (e.g. `GET /identity/api/v2/vehicle/vehicles` → `uuid`).
* crAPI's OpenAPI specification is in the cloned repository (`openapi-spec/`). It has no
  access-control annotations, so the intended policy must come from configuration.

## Ground-truth considerations

crAPI's documented challenges include several access-control flaws, for example:
- reading another user's vehicle location (BOLA),
- reading another user's mechanic report (BOLA),
- deleting another user's video through an admin-style endpoint (BFLA).

A ground-truth manifest for crAPI has **not** been written yet. Each case must be confirmed against the
running version of crAPI, because challenge details differ between releases. Unsupported scenarios
must be reported as such in the thesis. Examples are flaws that require e-mail interaction, chaining
several requests, or business-logic reasoning such as refunds or coupons.
