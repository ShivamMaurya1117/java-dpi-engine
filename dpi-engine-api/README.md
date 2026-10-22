# DPI REST API

Java 21, Spring Boot **3.5.16**, springdoc-openapi **2.9.1**. This sibling module depends on the existing core; the core and CLI remain independent of Spring.

From the repository root:

```powershell
mvn clean verify
java -jar dpi-engine-api/target/dpi-engine-api-1.0-SNAPSHOT.jar
```

The default address is `127.0.0.1:8080`. Health: `/actuator/health`; Swagger UI: `/swagger-ui/index.html`; OpenAPI JSON: `/v3/api-docs`.

Both POST endpoints accept multipart `file` (a classic PCAP) and optional `options` with `Content-Type: application/json`:

```json
{
  "workers": 4,
  "blockedApplications": ["DNS"],
  "blockedDomains": ["example.org"],
  "blockedIpv4Addresses": ["203.0.113.99"]
}
```

Omitted options, `{}`, and null/omitted workers mean one worker and no rules. Applications use the core AppType names (case insensitive); domains and IPv4 rules use core validation and matching. Workers must be JSON integers in 1–64 and must also fit the configured API worker limit (8 by default). Numeric strings, fractional workers (including `2.0`), booleans, unknown properties, malformed JSON, and non-string/null/blank rule entries are rejected. Each rule list permits at most 256 entries; omitted/null lists mean no rules.

```powershell
curl.exe -F "file=@test_dpi.pcap" http://127.0.0.1:8080/api/v1/dpi/analyze
curl.exe -F "file=@test_dpi.pcap" -F "options=@options.json;type=application/json" -o filtered.pcap http://127.0.0.1:8080/api/v1/dpi/filter
```

Analyze returns JSON packet counts, directional flow counts, application distribution, allowed/blocked counts, blocking reasons and processing duration in milliseconds. Filter returns `application/vnd.tcpdump.pcap` with attachment filename `filtered.pcap`; `X-DPI-Total-Packets`, `X-DPI-Allowed-Packets`, `X-DPI-Blocked-Packets`, and `X-DPI-Unique-Flows` report counts.

The defaults target a local learning/resume project. Configure environment variables before starting Java, or use the corresponding Spring properties:

| Environment variable | Spring property | Default |
| --- | --- | --- |
| `DPI_MAX_UPLOAD_SIZE` | `spring.servlet.multipart.max-file-size` | `25MB` |
| `DPI_MAX_REQUEST_SIZE` | `spring.servlet.multipart.max-request-size` | `26MB` |
| `DPI_MAX_CONCURRENT_REQUESTS` | `dpi.api.max-concurrent-requests` | `2` |
| `DPI_MAX_WORKERS_PER_REQUEST` | `dpi.api.max-workers-per-request` | `8` |
| `DPI_MAX_TOTAL_WORKERS` | `dpi.api.max-total-workers` | `16` |
| `DPI_MAX_PACKETS` | `dpi.api.max-packets` | `100000` |
| `DPI_MAX_FLOWS` | `dpi.api.max-flows` | `10000` |
| `DPI_MAX_PACKET_BYTES` | `dpi.api.max-packet-bytes` | `262144` (256 KiB) |
| `DPI_TEMP_DIRECTORY` | `dpi.api.temp-directory` | `${java.io.tmpdir}/dpi-engine-api` |

All budgets must be positive. Configuration caps are 16 concurrent requests, 64 workers/request, 256 total workers, and 64 MiB/captured record. Keep multipart request size larger than file size to allow overhead. A request's worker count must fit both worker limits. Busy request/combined worker permits return 429 immediately; there is no processing queue. Permits cover validation, processing, download copying, and cleanup, and are released on exceptions.

Every record counts against the record limit, including zero-length/uninspectable records. The flow limit counts distinct parsed directional five-tuples across all workers. Repeated packets in existing flows remain valid at the exact flow limit. Record allocation is checked before reading its body. The API uses a global pending window of 8 packets, so the pending captured data is bounded by 8 times the record-byte limit (plus transient copies and metadata). Upload, record, flow, queue and concurrency bounds work together; these are workload limits rather than an exact JVM heap quota. Increasing them raises memory/CPU/disk requirements.

Errors use JSON ProblemDetail responses:

| Status | Cause |
| --- | --- |
| 400 | Missing/empty file, invalid PCAP framing/PCAPNG, unsupported PCAP link type, malformed options/rules, invalid or over-policy workers |
| 413 | File/multipart size, record count, flow count, or captured-record byte budget exceeded; split/reduce the capture |
| 415 | Request is not multipart or options part has an unsupported media type; use `application/json` for options |
| 429 | Request or combined worker permits exhausted; retry later or request fewer workers |
| 500 | Genuine temporary storage/read/write/processing I/O failure |

Only Ethernet PCAP link type 1 (`DLT_EN10MB`) is accepted at the API boundary. Classic-PCAP framing is validated before processing; invalid metadata/truncation is distinguished from underlying storage failures. Individual unsupported or malformed network packets within Ethernet PCAPs retain the core's existing allow/skip semantics. This is offline packet inspection, not a guarantee that every network protocol is inspected.

Requests use unique temporary directories and new engine instances. Filter output is fully generated before response headers are set, then copied synchronously from disk to the servlet output stream using a bounded buffer; the application does not materialize a download byte array. The workspace remains owned until copying finishes. Input/output handles and permits are released on success, processing failure, or failed client transfer. Every file/directory deletion is attempted; cleanup failures are suppressed onto an existing exception, or reported as an I/O failure if there is no primary exception, and logged by the error handler.

Intentional limits: filesystem refusal or process termination can leave temporary files requiring manual removal after the service stops; there is no persistent janitor or crash recovery. Once a download response is committed, a later network/storage/cleanup failure cannot replace its HTTP status with a JSON problem. Slow downloads occupy bounded request permits until the synchronous transfer finishes; no wall-clock processing/download deadline is promised. Multipart spooling happens before application admission, so the servlet's upload limits do not provide a global disk quota. Keep the service local and provision writable temporary storage. Java cannot forcibly terminate code that ignores interruption; shutdown reports failure after two bounded waits. No TCP reassembly, HTTPS decryption, authentication, database, ML is added.

The root Maven reactor runs both modules. The existing core can still be built and run independently from `dpi-engine-java` with its existing CLI options.

See [VERIFICATION.md](VERIFICATION.md) for the PowerShell and Swagger verification guide.

Docker deployment: see [Docker setup and verification](../DOCKER.md).

## Project documentation

Start with the [project overview](../README.md), [detailed API contract](../docs/API.md), [architecture](../docs/ARCHITECTURE.md), and [request lifecycle diagrams](../docs/SEQUENCE.md). The configuration table above remains the reference for environment variables and Spring properties. Automated results and manual checks are documented in [VERIFICATION.md](VERIFICATION.md).
