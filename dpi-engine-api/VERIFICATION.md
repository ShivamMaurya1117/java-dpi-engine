# Verification guide

Run from the repository root with JDK 21 and Maven. Current synthetic capture: **12 records, 8 directional flows**, with **6 allowed / 6 blocked** using application DNS, domain example.org and IPv4 203.0.113.99 rules. Omitted rules retain all 12 records byte-for-byte. See [fixture specification](../docs/FIXTURE.md) and [API contract](../docs/API.md).

## Automated checks

```powershell
mvn clean verify
py -3 -m unittest discover -s tests -v
py -3 generate_test_pcap.py --check
```

The Python tests create only disposable temporary captures; `--check` reads the checked-in capture without overwriting it. Python is optional for Maven and Docker builds.

Final verification on 2026-10-22: **423 Maven tests** (344 core + 79 API), **3 Python tests**, zero failures/errors/skips. Java emits nonfatal dynamic-agent/class-sharing warnings during tests. Docker's Linux engine was unavailable; container checks remain pending. Use [DOCKER.md](../DOCKER.md) for the container build and verification procedure.

The suite covers protocol parsing, hostname extraction, rule evaluation, no-rule byte equality, sequential/parallel determinism, resource budgets, strict JSON validation, HTTP errors and temporary-file ownership. These regression tests do not establish throughput, peak heap or a global disk quota.

## Build and start

In PowerShell terminal 1:

```powershell
Set-Location D:\Projects\Packet_analyzer
mvn clean verify
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
New-Item -ItemType Directory -Force target/manual | Out-Null
java -jar dpi-engine-api/target/dpi-engine-api-1.0-SNAPSHOT.jar --dpi.api.temp-directory=D:/Projects/Packet_analyzer/target/manual/requests
```

The server remains in the foreground. In terminal 2:

```powershell
Set-Location D:\Projects\Packet_analyzer
$manualDir = Join-Path (Get-Location) 'target/manual'
New-Item -ItemType Directory -Force $manualDir | Out-Null
$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText("$manualDir/options.json", '{"workers":4,"blockedApplications":["DNS"],"blockedDomains":["example.org"],"blockedIpv4Addresses":["203.0.113.99"]}', $utf8)
[System.IO.File]::WriteAllText("$manualDir/invalid.json", '{"workers":"4"}', $utf8)
[System.IO.File]::WriteAllText("$manualDir/empty.json", '{}', $utf8)
$apiUrl = 'http://127.0.0.1:8080/api/v1/dpi'

$analysis = curl.exe -sS -F 'file=@test_dpi.pcap' -F "options=@$manualDir/options.json;type=application/json" "$apiUrl/analyze" | ConvertFrom-Json
$analysis | Format-List
if ($analysis.totalPackets -ne 12 -or $analysis.uniqueFlows -ne 8 -or $analysis.allowedPackets -ne 6 -or $analysis.blockedPackets -ne 6) { throw 'Demo analysis mismatch' }
curl.exe -sS -D "$manualDir/filter-headers.txt" -F 'file=@test_dpi.pcap' -F "options=@$manualDir/options.json;type=application/json" -o "$manualDir/filtered.pcap" "$apiUrl/filter"
Get-Content "$manualDir/filter-headers.txt"

# Count the downloaded records; the repository demo capture and output are little-endian.
$captureReader = [System.IO.BinaryReader]::new([System.IO.File]::OpenRead("$manualDir/filtered.pcap"))
try {
    if ($captureReader.ReadUInt32() -ne [uint32]2712847316) { throw 'Unexpected PCAP byte order/magic' }
    $captureReader.BaseStream.Position = 24
    $packetCount = 0
    while ($captureReader.BaseStream.Position -lt $captureReader.BaseStream.Length) {
        $null = $captureReader.ReadUInt32()
        $null = $captureReader.ReadUInt32()
        $capturedLength = $captureReader.ReadUInt32()
        $null = $captureReader.ReadUInt32()
        if ($capturedLength -gt ($captureReader.BaseStream.Length - $captureReader.BaseStream.Position)) { throw 'Truncated output' }
        $null = $captureReader.BaseStream.Seek($capturedLength, [System.IO.SeekOrigin]::Current)
        $packetCount++
    }
    if ($packetCount -ne 6) { throw "Expected 6 packets, got $packetCount" }
} finally { $captureReader.Dispose() }

# Omitted options and {} must return 200; no-rule filter must match input exactly.
curl.exe -sS -i -F 'file=@test_dpi.pcap' "$apiUrl/analyze"
curl.exe -sS -D "$manualDir/empty-headers.txt" -F 'file=@test_dpi.pcap' -F "options=@$manualDir/empty.json;type=application/json" -o "$manualDir/unfiltered.pcap" "$apiUrl/filter"
if ((Get-FileHash test_dpi.pcap).Hash -ne (Get-FileHash "$manualDir/unfiltered.pcap").Hash) { throw 'No-rule download changed' }
```

## Error and cleanup checks

Continue in terminal 2. These create disposable fixtures under `target`; the source
capture is never changed.

```powershell
# Unsupported link type 101, with otherwise intact classic-PCAP framing: 400 on both endpoints.
$unsupported = [System.IO.File]::ReadAllBytes((Join-Path (Get-Location) 'test_dpi.pcap'))
$linkBytes = [System.BitConverter]::GetBytes([uint32]101)
if ($unsupported[0] -eq 0xa1) { [array]::Reverse($linkBytes) }
[array]::Copy($linkBytes, 0, $unsupported, 20, 4)
[System.IO.File]::WriteAllBytes("$manualDir/unsupported.pcap", $unsupported)
foreach ($endpoint in @('analyze', 'filter')) {
    curl.exe -sS -i -F "file=@$manualDir/unsupported.pcap" -F "options=@$manualDir/options.json;type=application/json" "$apiUrl/$endpoint"
    # Numeric-string workers: 400.
    curl.exe -sS -i -F 'file=@test_dpi.pcap' -F "options=@$manualDir/invalid.json;type=application/json" "$apiUrl/$endpoint"
    # Missing file: 400. Wrong request type or options media type: 415.
    curl.exe -sS -i -F "options=@$manualDir/options.json;type=application/json" "$apiUrl/$endpoint"
    curl.exe -sS -i -H 'Content-Type: application/json' --data '{}' "$apiUrl/$endpoint"
    curl.exe -sS -i -F 'file=@test_dpi.pcap' -F "options=@$manualDir/options.json;type=text/plain" "$apiUrl/$endpoint"
}

# 100,001 complete zero-length records exceed the default 100,000-record budget: 413.
$demoBytes = [System.IO.File]::ReadAllBytes((Join-Path (Get-Location) 'test_dpi.pcap'))
$fixtureStream = [System.IO.File]::Create("$manualDir/record-budget.pcap")
try {
    $fixtureStream.Write($demoBytes, 0, 24)
    $emptyRecords = [byte[]]::new(16 * 100001)
    $fixtureStream.Write($emptyRecords, 0, $emptyRecords.Length)
} finally { $fixtureStream.Dispose() }
curl.exe -sS -i -F "file=@$manualDir/record-budget.pcap" "$apiUrl/analyze"
curl.exe -sS -i -F "file=@$manualDir/record-budget.pcap" "$apiUrl/filter"

# File-size and total multipart limits: 413.
$largeStream = [System.IO.File]::Create("$manualDir/large.bin")
try { $largeStream.SetLength(25MB + 1) } finally { $largeStream.Dispose() }
curl.exe -sS -i -F "file=@$manualDir/large.bin" "$apiUrl/analyze"
$partStream = [System.IO.File]::Create("$manualDir/part.bin")
try { $partStream.SetLength(14MB) } finally { $partStream.Dispose() }
curl.exe -sS -i -F "file=@$manualDir/part.bin" -F "padding=@$manualDir/part.bin" "$apiUrl/filter"

# A valid request after rejections must still succeed; request directories must be gone.
curl.exe -sS -i -F 'file=@test_dpi.pcap' "$apiUrl/analyze"
Get-ChildItem "$manualDir/requests" -Force
if (@(Get-ChildItem "$manualDir/requests" -Force).Count -ne 0) { throw 'Request workspace remains' }

# Deterministic 429/permit recovery plus injected failure/cleanup checks (MockMvc and service tests).
mvn -pl dpi-engine-api -am '-Dtest=DpiServiceHardeningTest' '-Dsurefire.failIfNoSpecifiedTests=false' test
```

To exercise flow and captured-byte limits with the demo capture, stop terminal 1
with Ctrl+C, restart once per command below, and run the indicated curl request
from terminal 2. Then stop and restore the normal startup command. No Java edits
are needed.

```powershell
# Terminal 1: 8 fixture flows exceed this policy.
java -jar dpi-engine-api/target/dpi-engine-api-1.0-SNAPSHOT.jar --dpi.api.max-flows=7
# Terminal 2: expect 413; repeat with /filter.
curl.exe -sS -i -F 'file=@test_dpi.pcap' http://127.0.0.1:8080/api/v1/dpi/analyze

# Terminal 1, after stopping the previous server: demo records exceed 64 captured bytes.
java -jar dpi-engine-api/target/dpi-engine-api-1.0-SNAPSHOT.jar --dpi.api.max-packet-bytes=64
# Terminal 2: expect 413; repeat with /filter.
curl.exe -sS -i -F 'file=@test_dpi.pcap' http://127.0.0.1:8080/api/v1/dpi/analyze

# Terminal 1, after stopping the previous server: intentionally unusable temporary directory.
[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'target/manual/storage-blocker'), 'not a directory')
java -jar dpi-engine-api/target/dpi-engine-api-1.0-SNAPSHOT.jar --dpi.api.temp-directory=D:/Projects/Packet_analyzer/target/manual/storage-blocker
# Terminal 2: expect 500.
curl.exe -sS -i -F 'file=@test_dpi.pcap' http://127.0.0.1:8080/api/v1/dpi/analyze
```

## Swagger requests

Open `http://127.0.0.1:8080/swagger-ui/index.html` with the normally configured server.
For both `POST /api/v1/dpi/analyze` and `POST /api/v1/dpi/filter`, choose **Try it out**,
select `test_dpi.pcap` as `file`, and enter this JSON in `options`:

```json
{"workers":4,"blockedApplications":["DNS"],"blockedDomains":["example.org"],"blockedIpv4Addresses":["203.0.113.99"]}
```

Expect 200; analysis reports 12 packets, 8 flows, 6 allowed, 6 blocked. Filter
offers a PCAP download with 6 packets and matching `X-DPI-*` count headers.
Omit options, use `{}`, or use `{"workers":null}`: expect 200 with no-rule defaults.
Select `target/manual/unsupported.pcap` with the demo JSON: expect 400
explaining Ethernet link type 1 is required. With the valid file, try each JSON:

```json
{"workers":"4"}
{"workers":1.5}
{"workers":9}
{"blockedApplications":[true]}
{"blockedDomains":[null]}
{"blockedIpv4Addresses":[123]}
{"unknownOption":1}
```

Each must return 400 with default configuration. Use `record-budget.pcap`: expect
413. For wrong media types, use the PowerShell requests above since Swagger sets
the multipart JSON encoding correctly. Read README.md for cleanup/crash, committed
response, non-cooperative worker, slow-client, and global disk-quota limitations.

