# VAmPI benchmark

[VAmPI](https://github.com/erev0s/VAmPI) is an intentionally vulnerable Flask API. It has a built-in
switch: `vulnerable=1` (default) or `vulnerable=0`. That gives a vulnerable and a patched mode of
the same application, like the thesis benchmark.

## Start

```bash
docker compose --profile external up -d vampi vampi-secure
```

```bash
curl -s http://localhost:5002/createdb
```

```bash
curl -s http://localhost:5003/createdb
```

Port 5002 runs the vulnerable mode and port 5003 the patched mode. `tokentimetolive` is set to 3600 s in
`docker-compose.yml`; VAmPI's default of 60 s would expire tokens during a scan. `GET /createdb`
re-seeds the database, so use it as the reset step between runs.

## Accounts (created by `/createdb`)

| username | password | role |
|---|---|---|
| name1 | pass1 | user |
| name2 | pass2 | user |
| admin | pass1 | admin (`admin: true`) |

Login: `POST /users/v1/login {"username","password"}` → `auth_token` (HS256 JWT, `sub` = username).
Each seeded user owns one book with a random title (`bookTitle<N>`), which a user can discover from
`GET /books/v1` (public).

## Configuration notes for an access-control tool

* **Identity = username.** Ownership in responses is expressed as `owner` (username), for example in
  `GET /books/v1/{book_title}`. Path parameters are `username` and `book_title` (not numeric IDs).
* **No access-control annotations** exist in the VAmPI spec. The intended policy must be supplied as
  configuration:
  - `GET /books/v1/{book_title}`: owner only (`ownerField: owner`)
  - `PUT /users/v1/{username}/password` and `PUT /users/v1/{username}/email`: owner only
  - `DELETE /users/v1/{username}`: admin only
  - `GET /users/v1/_debug`: admin only (it is unauthenticated in both modes)
* **Write effects are partly unobservable:** VAmPI has no endpoint that reads back a password, so a
  password change by another user can only be verified by logging in with the new password. That step
  is outside a generic tool. This case therefore tests whether a tool claims more than it can observe.
* The update endpoints answer **204 with a JSON body**, and the e-mail update always changes the *caller's*
  e-mail. Both are true negatives with 2xx status.

## Ground truth

`ground-truth.json` (vulnerable mode) and `ground-truth.secure.json` (patched mode) were labelled from
VAmPI's source code. Every case cites the function it was derived from (`source`). The scope is access
control only: SQL injection, mass assignment (`admin: true` at registration, OWASP API3), user
enumeration and ReDoS are out of scope and listed in the manifest.

| Category | Vulnerable mode | Patched mode |
|---|---|---|
| BOLA | 2 vulnerable / 1 secure | 0 / 3 |
| BFLA | 1 / 1 (`_debug` is vulnerable in both modes) | 1 / 1 |
| AUTH_* / JWT_* (6 bearer operations × 5) | 0 / 30 | 0 / 30 |

`openapi3.yml` is VAmPI's own specification (MIT License, © 2020 erev0s), copied unchanged except for an
attribution comment.

## Running ZAP against VAmPI

```bash
SPEC=benchmarks/vampi/openapi3.yml SPEC_SERVER=http://localhost:5000 LOGIN_PATH=/users/v1/login \
TOKEN_FIELD=auth_token RESET_PATH=/createdb RESET_METHOD=GET \
benchmarks/zap/run-zap.sh http://localhost:5002 evaluation/results/tmp/zap-vampi name1 pass1
```
