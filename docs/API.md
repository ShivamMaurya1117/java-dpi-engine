# REST API reference

[Overview](../README.md) · [Sequences](SEQUENCE.md) · [Configuration table](../dpi-engine-api/README.md) · [Verification plan](../dpi-engine-api/VERIFICATION.md)

Base URL for local startup: `http://127.0.0.1:8080`. Start the packaged API as described in the [README](../README.md). There is no authentication, database, saved job ID or asynchronous job endpoint.

## Endpoints and multipart contract

| Method and path | Request | Successful response |
| --- | --- | --- |
| `POST /api/v1/dpi/analyze` | `multipart/form-data` | 200 `application/json`, AnalysisResponse |
| `POST /api/v1/dpi/filter` | `multipart/form-data` | 200 `application/vnd.tcpdump.pcap`, binary file |

Both use required part **`file`** and optional part **`options`**. `file` contains classic-PCAP bytes; curl's default file-part media type is sufficient. The implementation validates contents, not a filename extension or a required file-part MIME string. Only Ethernet link type 1 (`DLT_EN10MB`) is accepted by this API. PCAPNG and other classic-PCAP link types return 400.

Send `options` with part content type **`application/json`**. Let curl generate the outer multipart boundary; do not manually set the request Content-Type header.

```json
{
  "workers": 4,
  "blockedApplications": ["DNS"],
  "blockedDomains": ["example.org"],
  "blockedIpv4Addresses": ["203.0.113.99"]
}
```

| Option | Default | Validation and semantics |
| --- | --- | --- |
| `workers` | 1 | JSON integer 1–64; also must fit API per-request and total-worker policy (defaults 8 and 16) |
| `blockedApplications` | No rules | At most 256 nonblank, non-null strings; case insensitive AppType names |
| `blockedDomains` | No rules | At most 256 nonblank, non-null hostname strings; exact root and dot-delimited subdomains |
| `blockedIpv4Addresses` | No rules | At most 256 nonblank, non-null strict dotted-decimal IPv4 strings; either endpoint |

Omitting options or using `{}` applies defaults. Omitted/null workers mean 1; omitted/null lists mean no rules. Unknown JSON properties, numeric strings, fractional workers including `2.0`, booleans, malformed JSON and non-string list elements are rejected. Null/blank list elements are rejected. Domain normalization lowercases and removes one trailing dot; whitespace is not trimmed. IPv4 rules reject leading-zero octets, CIDR and wildcards and do not resolve hostnames.

Accepted application names: `UNKNOWN`, `HTTP`, `HTTPS`, `DNS`, `TLS`, `QUIC`, `GOOGLE`, `FACEBOOK`, `YOUTUBE`, `TWITTER`, `INSTAGRAM`, `NETFLIX`, `AMAZON`, `MICROSOFT`, `APPLE`, `WHATSAPP`, `TELEGRAM`, `TIKTOK`, `SPOTIFY`, `ZOOM`, `DISCORD`, `GITHUB`, `CLOUDFLARE`. `TLS` and `QUIC` are reserved enum values; current classification does not emit them. `UNKNOWN` can be blocked explicitly, but unparseable network records bypass rules entirely.

## PowerShell requests

Run from the repository root in a second terminal with the API running. Using a JSON file avoids Windows native-command JSON quoting differences.

```powershell
curl.exe --fail-with-body -F 'file=@test_dpi.pcap' http://127.0.0.1:8080/api/v1/dpi/analyze
'{"workers":4,"blockedApplications":["DNS"],"blockedDomains":["example.org"],"blockedIpv4Addresses":["203.0.113.99"]}' | Set-Content -Encoding ascii options.json
curl.exe --fail-with-body -F 'file=@test_dpi.pcap' -F 'options=@options.json;type=application/json' http://127.0.0.1:8080/api/v1/dpi/analyze
curl.exe --fail-with-body -D filter-headers.txt -F 'file=@test_dpi.pcap' -F 'options=@options.json;type=application/json' -o api-filtered.pcap http://127.0.0.1:8080/api/v1/dpi/filter
```

Check `$LASTEXITCODE` after each curl request. With `--fail-with-body`, a non-2xx response still has an error body; when `-o` is used that body may be saved to the output path. Check status/headers before treating a saved file as a PCAP. Curl may overwrite a local destination file; this differs from the core writer's refusal to overwrite an existing CLI output.

## Successful analysis example

For the repository's `test_dpi.pcap` and the three demo rules above, the deterministic scenario contract and current tests support the following example. `processingDurationMs: 0.0` is an illustrative placeholder, not a measured value or guaranteed timing. Counts are specific to this fixture and options.

```json
{
  "totalPackets": 12,
  "parsedPackets": 12,
  "skippedPackets": 0,
  "tcpPackets": 8,
  "udpPackets": 4,
  "uniqueFlows": 8,
  "applicationDistribution": {
    "HTTP": 2,
    "HTTPS": 2,
    "DNS": 2,
    "UNKNOWN": 2
  },
  "allowedPackets": 6,
  "blockedPackets": 6,
  "writtenPackets": 0,
  "blockedFlows": 5,
  "blockingReasons": [
    {
      "type": "APPLICATION",
      "value": "DNS",
      "packets": 2
    },
    {
      "type": "DOMAIN",
      "value": "example.org",
      "packets": 3
    },
    {
      "type": "IPV4",
      "value": "203.0.113.99",
      "packets": 1
    }
  ],
  "processingDurationMs": 0.0
}
```

`applicationDistribution` counts final classifications once per directional flow, including blocked flows; its JSON key order is unspecified. Packet counts refer to complete PCAP records. Parsed counts include only supported Ethernet/IPv4 TCP/UDP packets; `skippedPackets = totalPackets - parsedPackets`. All records contribute to `allowedPackets + blockedPackets`. Analyze has `writtenPackets = 0` because it does not generate output. Blocking reason counts can overlap and retain the reasons from a flow's first block. Reasons are sorted by the core reason string representation. Duration measures the core processing call including its I/O/resource closure, excluding API prevalidation and transfer.

Without rules this fixture reports 12 allowed, 0 blocked, 0 blocked flows and an empty blockingReasons array. Its flow distribution remains the same. See [current fixture design and verification](FIXTURE.md); duration remains illustrative.

## Filter response

For demo rules, the current fixture download contains 6 records and 575 bytes. Headers are:

```http
Content-Type: application/vnd.tcpdump.pcap
Content-Disposition: attachment; filename="filtered.pcap"
Content-Length: 575
X-DPI-Total-Packets: 12
X-DPI-Allowed-Packets: 6
X-DPI-Blocked-Packets: 6
X-DPI-Unique-Flows: 8
```

There is no JSON response body on successful filtering. The completed file is copied synchronously from the workspace into the servlet stream, then deleted. The output preserves global header properties and each retained record's bytes, timestamp, captured/original lengths and relative order. A no-rule download of this fixture matches its input bytes. Unsupported network records are retained too. Counts and length depend on the input and rules.

## Resource policy

Defaults: 25 MB file, 26 MB multipart request, 2 admitted requests, 8 workers/request, 16 combined worker permits, 100000 records, 10000 directional flows and 262144 captured bytes/record. Spring's `MB` sizes are binary units. Each request reserves its requested workers even in one-worker sequential mode and retains permits through download/cleanup. Busy permits return 429 immediately. Validation itself reads all records before the core processing pass.

The parallel API pending window is 8 records, not 8 records per worker. Default pending captured data is therefore bounded by 8 × 262144 bytes, plus transient copies, flow tables, task objects and other memory. This is not an exact heap guarantee. Complete zero-length and unsupported records still count against record budgets. Existing flows remain admissible at the exact flow-count limit.

The full environment-variable/Spring-property table is maintained in the [API module README](../dpi-engine-api/README.md). Positive configuration caps: 16 concurrent requests, 64 workers/request, 256 total workers and 64 MiB per record. CLI defaults do not inherit API budgets.

## Errors and transfer limitations

Errors are JSON ProblemDetail responses, normally `application/problem+json`. They contain status/title/detail (and framework-supplied fields such as instance when available); do not assume every detail string is a stable API identifier.

| HTTP status | Implemented cause |
| --- | --- |
| 400 | Missing/empty file; invalid/truncated classic PCAP or PCAPNG; non-Ethernet link type; malformed/unknown JSON fields, invalid rules, or worker count outside validation/configured policy |
| 413 | Servlet upload/request size, service upload size, record count, flow count or configured captured-record byte budget exceeded |
| 415 | Wrong outer request media type or unsupported options-part media type |
| 429 | No request permit or insufficient combined worker permits; retry later/request fewer workers |
| 500 | Genuine temporary-file, read, write, processing or cleanup I/O failure |

A record larger than the reader's absolute 64 MiB ceiling is invalid PCAP metadata (400 in prevalidation); a record above a smaller configured byte budget produces 413. Malformed individual network packets in valid framing are skipped/allowed rather than errors.

Example problem for unsupported link type 101 (additional framework fields may appear):

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "Unsupported PCAP link type 101; Ethernet (link type 1, DLT_EN10MB) is required. Upload an Ethernet PCAP capture."
}
```

Before a filter response is committed, failures reset download headers and can return a JSON problem. Once committed, a transfer/storage/cleanup failure cannot replace the existing response with a new status/body. A partial download is possible. Slow clients occupy permits; there is no wall-clock processing/download deadline. Filesystem refusal or process termination may leave workspaces. Multipart spooling precedes admission, so request permits do not establish a global disk quota. See [sequence diagrams](SEQUENCE.md) for cleanup order.

## Swagger and verification

Open `http://127.0.0.1:8080/swagger-ui/index.html`, select either POST operation, choose **Try it out**, upload `test_dpi.pcap` as `file`, and enter the demo JSON as `options`. The OpenAPI encoding marks options as JSON and the filter response as binary. The live schema is at `/v3/api-docs`; health is `/actuator/health` (only actuator health is exposed).

The [verification plan](../dpi-engine-api/VERIFICATION.md) contains negative requests and workspace checks. [docker-verify.ps1](../docker-verify.ps1) verifies the running container's demo results, downloaded framing, determinism and selected errors.
