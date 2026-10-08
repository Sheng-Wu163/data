# Banner Fingerprint System

A small, production-oriented banner fingerprinting service written in Go. It
takes raw network scan data (`ip`, `port`, `banner`), identifies the protocol,
software and version behind each banner, and returns a structured verdict. It
ships as a **client + server** pair and starts with a single
`docker compose up`.

```
[ raw JSON ] --(client)--> POST /fingerprint --(server: rule engine)--> [ verdicts JSON ]
```

## Quick start

```bash
docker compose up --build
```

Compose builds both images, waits for the server's health check to pass, then
runs the client against `testdata/input.json`. The identified results are
printed to the client's stdout (`docker compose logs client`).

To fingerprint your own data, drop a JSON file into `./testdata/` (or point the
`CLIENT_INPUT` environment variable / the `-input` flag at another path) and
re-run.

## API

### `GET /health`

Readiness/liveness probe. Returns `200` with:

```json
{"status":"ok","rules":10,"time":"2026-01-01T00:00:00Z"}
```

### `POST /fingerprint`

Accepts a JSON **array** of inputs (an `{"items":[...]}` envelope and a single
object are also accepted) and returns a JSON array of results in the same
order.

Request:

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
]
```

Response:

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9}
]
```

Result fields:

| field        | meaning                                                        |
|--------------|----------------------------------------------------------------|
| `ip`         | echoed from the input                                          |
| `port`       | echoed from the input                                          |
| `protocol`   | `SSH`, `HTTP`, `MySQL`, `Redis`, `FTP`, `TLS`, or `unknown`    |
| `product`    | software name (e.g. `nginx`, `OpenSSH`), or `""`               |
| `version`    | version string, or `""`                                        |
| `os_hint`    | OS inferred from the banner (e.g. `Ubuntu`), or `""`           |
| `confidence` | number in `[0,1]`                                              |

Anything that cannot be identified returns `protocol:"unknown"` with empty
fields — **unrecognised input is never an error and never crashes the server**.

## Supported fingerprints

| Protocol | Products / variants                                   |
|----------|-------------------------------------------------------|
| SSH      | OpenSSH (and other `SSH-x.y-<product>_<ver>` daemons) |
| HTTP     | nginx, Apache, Jetty, Microsoft-IIS, generic HTTP      |
| MySQL    | MySQL handshake (protocol 0x0a)                        |
| Redis    | `+OK`/`+PONG`/`-ERR`/`-NOAUTH` replies                |
| FTP      | ProFTPD, vsFTPd, Pure-FTPd, FileZilla, wu-ftpd, Serv-U |
| TLS      | TLS ClientHello / ServerHello record header           |

## Layout

```
cmd/server/          server binary (HTTP service)
cmd/client/          client binary (file -> server -> stdout)
internal/api/        HTTP handlers + middleware
internal/fingerprint/identification engine (rule evaluation)
internal/model/      wire types + tolerant input parser
internal/normalize/  canonicalisation of "almost-raw" banners
rules/               rule engine + embedded default ruleset (rules.json)
testdata/            self-test and edge-case input files
Dockerfile           multi-stage build (server + client targets)
docker-compose.yml   one-command deployment
```

## Rule engine — rules as data, not code

Fingerprints live in [`rules/rules.json`](rules/rules.json), completely
separate from the Go code. Each rule is:

```json
{
  "name": "http-nginx",
  "protocol": "HTTP",
  "priority": 86,
  "require_all": ["(?i)server:\\s*nginx"],
  "product_default": "nginx",
  "version_regex": "(?i)nginx/?\\s*([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)",
  "os_rules": [{"regex": "(?i)ubuntu", "os": "Ubuntu"}],
  "confidence": 0.9
}
```

- `require_all` — every regex must match.
- `require_any` — at least one must match (optional).
- `priority` — higher runs first; the first matching rule wins.
- `product_regex` / `product_default` — first capture group, or a fallback.
- `version_regex` — first capture group is the version.
- `os_rules` — first matching fragment yields the `os_hint`.
- `confidence` — reported when the rule fires.

Adding coverage means editing JSON, not code. The default set is embedded into
the binary via `go:embed`; setting `RULES_PATH` (as compose does) loads an
external file instead, so rules can be updated without rebuilding.

## Running without Docker

```bash
go test ./...                        # unit + API tests
go run ./cmd/server                  # starts on :8080
go run ./cmd/client -input testdata/input.json
```

## Production / hardening notes

- **Converged container access** — the client talks to the server by service
  name over a dedicated bridge network; the server is published only on
  `127.0.0.1`, never externally.
- **Real health dependency** — the client waits for `service_healthy`, backed
  by an actual HTTP probe (the server binary probes its own `/health`).
- **Compile/packaging** — multi-stage build, `CGO_ENABLED=0` static binary,
  `-trimpath -ldflags="-s -w"`, builder stage discarded from the runtime image.
- **Least privilege** — non-root uid/gid `10001`, read-only root filesystem,
  all capabilities dropped, `no-new-privileges`, `tmpfs` for `/tmp`.
- **Robustness** — bounded request size, graceful shutdown, panic-safe
  per-banner matching, tolerant input parsing.

## Testing

`go test ./...` covers:

- exact identification of every self-test fixture (protocol/product/version/
  os_hint/confidence);
- edge cases: empty banners, binary garbage, oversized banners, SMTP `220`
  greetings (must **not** be misread as FTP), non-ASCII bytes;
- literal `\x00` escape normalisation;
- batch ordering/length and empty-batch behaviour;
- HTTP API: health, array/envelope/single-object bodies, empty array, malformed
  JSON (`400`), wrong method (`405`).
