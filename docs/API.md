# YesWeHack API reference

This MCP server wraps the YesWeHack REST API at `https://api.yeswehack.com`. This page links the official documentation, explains authentication and pagination, and maps each MCP tool to the endpoint it calls.

## Official documentation

- OpenAPI spec: https://api.yeswehack.com/doc.json
- Redoc browser: https://api.yeswehack.com/doc
- Personal Access Token help-center article: https://helpcenter.yeswehack.io/en/articles/380967-api-personal-access-tokens
- Official Python SDK: https://pypi.org/project/yeswehack/
- ywh2bugtracker: https://github.com/yeswehack/ywh2bugtracker

## Authentication

- **Personal Access Token (documented).** Send the token in the `X-AUTH-TOKEN` header.
- **Session JWT (undocumented, mirrors the official SDK).** Send it as `Authorization: Bearer <token>`. Obtain it like this:
  1. `POST /login` returns either `token` or `totp_token`.
  2. If `totp_token` is returned, `POST /account/totp` with `{"token": <totp_token>, "code": <6 digits>}` returns `token`.

`/user`, `/user/email-aliases`, `/v2/hacktivity` and `/login` are outside the PAT spec.

## Pagination

Report, program and per-program hacktivity list endpoints accept the query parameters `page` and `resultsPerPage`. The response contains `pagination` with `page`, `nb_pages`, `results_per_page` and `nb_results`, plus the list in `items`. The OpenAPI schema `Pagination` lists these four fields flat; the live API returns them nested under `pagination`.

## Tool to endpoint map

| Tool | Endpoint | In PAT spec |
|---|---|---|
| get_current_user | GET /user | no (JWT session route; 403 for PAT) |
| list_programs | GET /programs | yes |
| get_program | GET /programs/{slugOrPid} | yes |
| list_reports | GET /programs/{slug}/reports?filter[status][]=&page=&resultsPerPage= | yes |
| get_report | GET /reports/{id} | yes |
| list_report_comments | GET /reports/{id}/logs | yes |
| list_email_aliases | GET /user/email-aliases | no (JWT; 403 for PAT) |
| get_program_credentials | GET /programs/{slug}/hunter/credentials | yes (hunter role; 403 for a manager/auditor PAT) |
| request_program_credentials | POST /programs/{slug}/hunter/ask-credentials/{pool_slug}/{classic,email,email-alias}; body `{"emails": [...]}` only for `email` (spec: "Only for 'email' demand"), 204 No Content | yes (WRITE) |
| yeswehack_api_get | any GET | - |
| get_hacktivity | GET /v2/hacktivity (public) | no (public, undocumented) |
| authenticate | POST /login, POST /account/totp (JWT flow) | no |

Write operations: only `request_program_credentials` writes to YesWeHack. `authenticate` obtains a session token (API login, direct token or browser login) and stores it locally; it never changes anything on YesWeHack.

## Report filters

`filter[status][]` values: invalid, wont_fix, resolved, out_of_scope, duplicate, spam, not_applicable, informative, rtfs, auto_close, new, more_info, under_review, accepted.

Other filters:

- `filter[criticity][]`: N, L, M, H, C
- `filter[triageStatus][]`: not_available, in_progress, assessed, awaiting_info, done
- `filter[trackingStatus][]`: U, AFI, T
- `filter[search]` (string)
- `filter[sortBy]`: criticity, priority, identifier, changedAt
- `filter[order]`: ASC, DESC

## Verifying against the spec

Download the spec and list its paths:

```bash
curl -s -A 'Mozilla/5.0' -o doc.json https://api.yeswehack.com/doc.json
python3 - <<'PY'
import json
spec = json.load(open("doc.json"))
for path in sorted(spec["paths"]):
    print(path, *spec["paths"][path])
PY
```

`make test-live` runs read-only checks against the real API (needs `YWH_PAT`).
