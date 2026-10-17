# vettid-calls

The VettID calling service: the **media plane** of 1:1 voice calls between
VettID connections. It has two parts:

- **A STUN/TURN server**: [coturn](https://github.com/coturn/coturn)
  4.18.0, pinned by digest, with `turn-agent` beside it. STUN tells a phone
  its own public address so that two phones can find a direct path; TURN
  forwards a call's packets when no direct path exists. What it forwards is
  already encrypted end to end under keys it never has.
- **A credential issuer** (`vettid-calls`): one HTTPS endpoint that gives
  short-lived TURN credentials to **attested VettID vaults only**. The
  shared secret never enters a vault, an app or a phone.

- **Protocol:** CALLING-SERVICE **0.2.0** (`docs/CALLING-SERVICE.md` in
  [vettid.org](https://github.com/vettid/vettid.org)), reported by
  `vettid-calls -version`. The vault's side is VAULT-MESSAGING §10.10
  ("Vault-signed ICE configuration", "Servers and credentials").
- **Only caller of the issuer:** a VettID vault. Apps, desktops, members
  and agents never talk to it; a device gets servers and credentials only
  from its own vault, inside a configuration the vault signs.
- **No state.** The issuer has no database, no cache, no replay cache and
  no file; it writes nothing. The TURN server holds only the secret and the
  allocations of calls being relayed now.
- **Usernames name nobody.** A username is `<expiry>:<16 random bytes>`;
  it carries no call, vault, member, device or connection.
- **Counters only.** No log line per request, credential, allocation or
  call; no address or username in any metric (§10). coturn's own log is
  read by `turn-agent` in memory and dropped.
- **Stack:** Go standard library `net/http`. The attestation and manifest
  verifiers and the pinned AWS Nitro root are the vault's own packages
  (`vettid-vault/vms/nitro`, `vms/manifest`, `vms/pins`), wrapped exactly as
  the push gateway wraps them; request signatures are the relay's
  (`vettid-relay/relayauth`). The AWS SDK for Go v2 is used for Secrets
  Manager and CloudWatch, `aws-lambda-go` for the function runtime. No
  CGO; the binaries are static.

## What is in this repository

| Path | What |
|---|---|
| `cmd/vettid-calls` | The credential issuer: an AWS Lambda function (behind CloudFront) or an HTTP server |
| `cmd/turn-agent` | The server image's entry point: secret → coturn configuration → coturn → metrics |
| `cmd/callsctl` | The operator tool: the secret's lifecycle and test credentials |
| `internal/turnagent/turnserver.conf.tmpl` | coturn's configuration template (§7.2) |
| `Dockerfile` | The server image: coturn 4.18.0 + `turn-agent` |
| `Dockerfile.issuer` | The issuer's function archive (`bootstrap` for `provided.al2023`, arm64) |
| `internal/attest` | Attestation and manifest checks, shared with `vettid-push` (see "Shared code") |
| `internal/turncred` | Usernames, credentials and the secret document; `testdata/vectors.json` |

## Quick start (the development stand-in)

The issuer's `-dev` mode accepts the development enclave's TEST
attestation root and a fixed list of PCR0s, so a development vault can get
credentials without the release manifest. It refuses the AWS root.

```sh
make build
CALLS_TURN_HOST=localhost \
CALLS_DEV_NITRO_ROOT_FILE=/path/to/dev-enclave-test-root.pem \
CALLS_DEV_PCR0S=<96 hex digits> \
CALLS_LISTEN_ADDR=127.0.0.1:8080 \
  bin/vettid-calls -dev
curl -s http://127.0.0.1:8080/v1/health    # {}
```

Without `CALLS_SECRETS` the stand-in makes a random secret at start
(`CALLS_SECRETS=file` with `CALLS_SECRET_FILE` lets a local coturn share
it). Never run `-dev` where a real vault can reach it.

## The secret

One JSON document, held in a secret store, read by the issuer and by
`turn-agent` at start and every 10 minutes:

```json
{ "current": "<id>", "secrets": { "<id>": "<base64 of 32 random bytes>" } }
```

The issuer signs with `current`; the server accepts every listed secret.
**No deployment tool creates it; the operator does:**

```sh
# first secret
callsctl secret new | aws secretsmanager create-secret \
  --name vettid-org/staging/calls/turn-secret --kms-key-id alias/vettid-org-calls \
  --secret-string file:///dev/stdin
# monthly rotation: add a secret and make it current ...
aws secretsmanager get-secret-value --secret-id vettid-org/staging/calls/turn-secret \
  --query SecretString --output text | callsctl secret rotate | \
  aws secretsmanager put-secret-value --secret-id vettid-org/staging/calls/turn-secret \
  --secret-string file:///dev/stdin
# ... and a day later (longer than a credential's 6 hours) drop the old one
...  | callsctl secret drop <old id> | ...
callsctl secret list < doc     # ids and the current one, never a value
```

The output of `new`, `rotate` and `drop` **is the secret**: pipe it
straight into the store, never into a file or a terminal log. A secret is
never deleted and created again.

coturn 4.18.0 reads its secrets only at start, so `turn-agent` restarts it
when the document changes: **calls being relayed at that moment drop**
(direct calls are not affected). Rotate when that is acceptable.

## The server image

```sh
docker run --network host --read-only --log-driver none \
  --tmpfs /run/vettid-calls:rw,mode=0700,uid=65534,gid=65534 \
  -e CALLS_TURN_HOST=turn.example.org \
  -e CALLS_PRIVATE_IPV4=10.0.0.12 -e CALLS_PUBLIC_IPV4=203.0.113.20 \
  -e CALLS_IPV6=2001:db8::20 -e CALLS_OWN_NETWORKS=10.0.0.0/16,2001:db8::/56 \
  -e CALLS_SECRET_ID=my/turn-secret -e AWS_REGION=us-east-1 \
  -e CALLS_METRICS_NAMESPACE=calls \
  ghcr.io/vettid/vettid-calls/turn@sha256:<digest>
```

- **Host networking**: the relay uses UDP 49152–65535. Open inbound UDP
  3478, TCP 3478 and UDP 49152–65535 (IPv4 and IPv6) and nothing else.
- **`--log-driver none`**: coturn's log names every client address and
  username. `turn-agent` reads it through a pipe, counts allocation
  refusals and drops each line; nothing should keep the container's
  output either.
- **The tmpfs** holds the rendered configuration (it contains the
  secrets) and coturn's pid file. Nothing is written elsewhere.
- `turn-agent -print-config` prints the configuration it would render,
  with the secrets replaced by `REDACTED`.

### turn-agent configuration

| Variable | Default | Meaning |
|---|---|---|
| `CALLS_TURN_HOST` | (required) | The server's name: coturn's realm and server name |
| `CALLS_PRIVATE_IPV4` | (required) | The address coturn listens on and relays from |
| `CALLS_PUBLIC_IPV4` | (required) | The public address phones reach (coturn's `external-ip` mapping) |
| `CALLS_IPV6` | (none) | The fixed IPv6 address, listened on and relayed from |
| `CALLS_OWN_NETWORKS` | (none) | The service's own network blocks (CIDR), denied as peers |
| `CALLS_SECRETS` | `aws` | `aws` (Secrets Manager) or `file` |
| `CALLS_SECRET_ID` / `CALLS_SECRET_FILE` | | The secret's id, or a file holding the document |
| `AWS_REGION` | | For Secrets Manager and CloudWatch |
| `CALLS_METRICS` | `cloudwatch` | `cloudwatch` (PutMetricData), `emf` (standard output) or `none` |
| `CALLS_METRICS_NAMESPACE` | `vettid-calls` | e.g. `vettid-org/staging/calls` (§10) |
| `CALLS_MAX_KBPS` | `256` | Bandwidth per allocation, each direction, kbit/s (D15; 3000 with video, C4) |
| `CALLS_CAPACITY_KBPS` | `120000` | Bandwidth in total, kbit/s: 40 allocations at C4's 3000 (see "Caps" below) |
| `CALLS_USER_QUOTA` / `CALLS_TOTAL_QUOTA` | `10` / `100` | Allocations per credential / in total |
| `CALLS_RUN_DIR` | `/run/vettid-calls` | The tmpfs |
| `CALLS_TURNSERVER` | `/usr/bin/turnserver` | coturn's binary |

### Metrics of the server (once a minute)

`allocations` (current), `allocations_refused{reason}` (`quota_user`,
`quota_total`, `capacity`), `auth_failures`, `bytes_relayed`,
`stun_bindings`, `heartbeat`; and, beyond §10, `coturn_restarts{reason}`
(`secret`, `exit`) and `agent_errors{kind}`. `bytes_relayed` counts bytes
coturn sent to clients and peers **of finished sessions** (that is what
coturn's Prometheus counters hold): a long call is counted when it ends.
For a cost alarm the instance's own `NetworkOut` is the better measure.

## The issuer

### Deployment

On VettID's staging, the issuer is the function archive
(`make archive`; CI publishes it as a release asset) on AWS Lambda
(`provided.al2023`, arm64, reserved concurrency 4), behind a function URL
and a CloudFront distribution with an ACM certificate: the vault's
enclave reaches it only over TLS 1.3 and HTTP/2 with an Amazon root
(CALLING-SERVICE §5.5, §8.2). Recommended function settings:

- log format JSON with **system log level WARN**, so that Lambda writes no
  START/END/REPORT line per invocation (§3 item 5, §10);
- a role with `secretsmanager:GetSecretValue` on the one secret,
  `kms:Decrypt` through Secrets Manager, and `cloudwatch:PutMetricData`
  limited to the namespace;
- CloudFront's access log off for this name.

Anywhere else it runs as an HTTP server (`CALLS_LISTEN_ADDR`) behind a
TLS terminator.

### Issuer configuration

| Variable | Default | Meaning |
|---|---|---|
| `CALLS_CHANNEL` | (required) | `prod` or `staging`: selects the compiled-in manifest URL and keys |
| `CALLS_TURN_HOST` | (required) | The TURN server's name, put into the URLs |
| `CALLS_LISTEN_ADDR` | `:8080` | HTTP server mode only |
| `CALLS_MAX_INFLIGHT` | `4` | Requests handled at once; more are answered 429 (§7.5) |
| `CALLS_SECRETS` | `aws` | `aws`, `file` or `env` (`none` under `-dev`: a random secret) |
| `CALLS_SECRET_ID` / `CALLS_SECRET_FILE` / `CALLS_SECRET_ENV` | | Where the document is |
| `AWS_REGION` | | For Secrets Manager and CloudWatch |
| `CALLS_METRICS` | `cloudwatch` in Lambda, else `emf` | `cloudwatch`, `emf` or `none` |
| `CALLS_METRICS_NAMESPACE` | `vettid-calls/<channel>` | e.g. `vettid-org/staging/calls` |
| `CALLS_LOG_LEVEL` | `info` | `info`, `warn` or `error` |
| `CALLS_DEV_NITRO_ROOT[_FILE]`, `CALLS_DEV_PCR0S` | | `-dev` only |

### API

```
POST /v1/credentials
X-VettID-Key:         <base64 Ed25519 public key, made for this one request>
X-VettID-Timestamp:   <RFC 3339>
X-VettID-Sig:         <signature per RELAY-PROTOCOL §4.1>
X-VettID-Attestation: <base64 Nitro attestation document>
{ "count": 1..4 }

→ 200 { "stun": ["stun:<host>:3478"],
        "turn": ["turn:<host>:3478?transport=udp", "turn:<host>:3478?transport=tcp"],
        "credentials": [ { "username": "<expiry>:<random>", "credential": "<base64>", "exp": <unix s> } ] }

GET /v1/health → 200 {}
```

In order: 429 `rate_limited` when 4 requests are in flight; 400 for a
body over 1 KiB; 401 `signature_invalid` / `timestamp_stale` (90 s);
403 `attestation_invalid` for every attestation failure alike; 400
`bad_request` for a body other than `{"count": 1..4}`; 500 `internal`
when no secret could be read. Error bodies are
`{"code","message","retry_after"?}` (RELAY-PROTOCOL §7.1).

The attestation rules are PUSH-GATEWAY §5.1 step 2, unchanged: the chain
ends at the pinned AWS Nitro Enclaves root; `timestamp` within 300 s;
`public_key` = the request's key; `user_data` = the request's digest;
PCR0 = an `active` or `deprecated` release of the channel's signed
manifest. The manifest is fetched and verified under the pinned keys,
never at a lower serial, refreshed when 10 minutes old (by the wall clock:
a function is frozen between requests), and trusted for at most 7 days
after the last successful refresh.

### Metrics and logs of the issuer

Metrics: `requests{outcome}`, `attestation_failures{reason}`,
`manifest_refresh{outcome}`, `internal_errors`, and (beyond §10)
`secret_refresh{outcome}`; every value from a closed set. In Lambda they
are put with PutMetricData after each request (standard resolution, so
CloudWatch keeps them per minute); as a server, EMF lines once a minute.
Logs: one start line, and errors of the service at most once a minute
per kind. Never a key, a document, a username, a credential or an
address; the source address is not even read.

## Shared code

The issuer must verify attestations exactly as the push gateway does
(CALLING-SERVICE §4.2). `vettid-push` keeps its wrapper under `internal/`,
which Go does not let another module import, so `internal/attest` and
`internal/nsmtest` are **copied** from `vettid-push` (commit
`7dda46f5f8f7`) with attribution and marked changes. The verifiers they
wrap (the Nitro document, the manifest, the pinned root) are **not
copied**: they are the vault's own packages, imported from `vettid-vault`
at the version `vettid-push` pins. Moving the wrapper to an importable
package (in `vettid-vault/vms` or a public path of `vettid-push`) would
let both import it; until then keep the two in step.

## Spec interpretation notes

- **HMAC key (§5.3).** The secret is stored as base64 text; coturn uses
  the configured string's bytes as the HMAC key, so the issuer does too
  (it does not decode the base64). The vectors in
  `internal/turncred/testdata/vectors.json` were written here: the
  specification has none.
- **Caps (§7.2).** coturn's `max-bps` and `bps-capacity` are bytes per
  second: 256 kbit/s is `max-bps=32000`, 120 Mbit/s is
  `bps-capacity=15000000`. coturn reserves `max-bps` from the capacity
  for **every allocation, used or not** (the last one admitted gets what
  is left), and a phone's WebRTC keeps every relay allocation it made for
  the life of the call: one per TURN URL (UDP and TCP) per network, so 2
  to 4 per phone and up to 8 per call, whether the call ends up relayed
  or direct. The capacity is therefore sized in allocations: 120 Mbit/s
  is **40 allocations at C4's 3 Mbit/s** (D15), five video calls at the
  worst count of 8, which is every call staging's at most ten testers can
  hold at once. While calls are voice only it admits 469, so
  `total-quota=100` binds first (12 to 25 calls). (The capacity was 4
  Mbit/s, 15 or 16 voice allocations and a single one at 3 Mbit/s.) What
  bounds cost is the daily stop at 30 GB (§7.3), not this cap; the media
  actually relayed is far below it (a relayed side of a 720p call is 1 to
  2.5 Mbit/s each way), and 120 Mbit/s stays under a `t4g.small`'s
  baseline network bandwidth (128 Mbit/s).
- **Defaults (§7.2).** In coturn 4.18.0 RFC 5780, the SOFTWARE attribute,
  pre-RFC 5389 compatibility, the CLI, the web admin and DTLS are all off
  unless switched on; the deprecated `no-…` forms are not written.
- **Refusals (§10).** coturn 4.18.0 has no Prometheus counter for refused
  allocations and logs them only in verbose mode; `turn-agent` runs coturn
  verbose and counts the lines in memory. `quota_total` and `quota_user`
  share one log text; `turn-agent` tells them apart by the current
  allocations.
- **No replay cache (§5.2).** A request replayed within its 90 s window
  is answered again with other credentials, by design.
- **Expiry.** coturn refuses a username whose expiry is before now, on
  every authenticated request, including the refreshes a client sends at
  least every 10 minutes; so an allocation should end within about 10
  minutes of its credential's expiry. CALLING-SERVICE §13 tests it.

## Development

```sh
make test          # go test -p 1 ./...
make race          # go test -race -p 1 ./...
make lint          # go vet + staticcheck (pinned, via go run)
make scan          # gitleaks over history
make image         # the server image
make image-repro   # two clean builds of the image, compared
make archive       # the issuer's archive, built in the pinned toolchain image
make archive-repro # two clean builds of the archive, compared
make archive-local # the archive with the local toolchain
```

No test contacts AWS, a manifest site or a real enclave: the manifest site
is a local server, the Nitro attestation comes from a test NSM with its
own throwaway PKI, and every key is generated when the test runs.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE). coturn is BSD-3-Clause and is
used unmodified, as the coturn project's own image.
