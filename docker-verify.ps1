$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$base = 'http://127.0.0.1:8080'
$work = Join-Path ([IO.Path]::GetTempPath()) ('dpi-docker-check-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
function Check($ok, $message) {
    if (-not $ok) { throw $message }
}
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $health = Invoke-RestMethod "$base/actuator/health"
            if ($health.status -eq 'UP') { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 1
    }
    Check $ready 'API did not become healthy within 60 seconds'
    Check ((Invoke-WebRequest -UseBasicParsing "$base/swagger-ui/index.html").StatusCode -eq 200) 'Swagger failed'
    $spec = Invoke-RestMethod "$base/v3/api-docs"
    Check ($null -ne $spec.paths.'/api/v1/dpi/analyze') 'OpenAPI analyze endpoint missing'
    $options = Join-Path $work 'options.json'
    [IO.File]::WriteAllText($options, '{"workers":4,"blockedApplications":["DNS"],"blockedDomains":["example.org"],"blockedIpv4Addresses":["203.0.113.99"]}')
    $analysisText = & curl.exe --fail-with-body -sS -F 'file=@test_dpi.pcap' -F "options=@$options;type=application/json" "$base/api/v1/dpi/analyze"
    Check ($LASTEXITCODE -eq 0) 'Analyze request failed'
    $analysis = $analysisText | ConvertFrom-Json
    Check ($analysis.totalPackets -eq 12 -and $analysis.uniqueFlows -eq 8 -and $analysis.allowedPackets -eq 6 -and $analysis.blockedPackets -eq 6) "Unexpected analysis: $analysisText"
    $output = Join-Path $work 'filtered.pcap'
    $headers = Join-Path $work 'headers.txt'
    & curl.exe --fail-with-body -sS -D $headers -F 'file=@test_dpi.pcap' -F "options=@$options;type=application/json" -o $output "$base/api/v1/dpi/filter"
    Check ($LASTEXITCODE -eq 0) 'Filter request failed'
    Check ((Get-Content $headers -Raw) -match 'X-DPI-Allowed-Packets: 6') 'Filter count header missing'
    # Re-upload to validate PCAP framing and independently count the downloaded records.
    $recheckText = & curl.exe --fail-with-body -sS -F "file=@$output" "$base/api/v1/dpi/analyze"
    Check ($LASTEXITCODE -eq 0) 'Downloaded PCAP is invalid'
    Check (($recheckText | ConvertFrom-Json).totalPackets -eq 6) 'Downloaded PCAP must contain 6 packets'
    $second = Join-Path $work 'filtered-again.pcap'
    & curl.exe --fail-with-body -sS -F 'file=@test_dpi.pcap' -F "options=@$options;type=application/json" -o $second "$base/api/v1/dpi/filter"
    Check ($LASTEXITCODE -eq 0) 'Repeated filter failed'
    Check ((Get-FileHash $output).Hash -eq (Get-FileHash $second).Hash) 'Filtering is not deterministic'
    foreach ($workers in @(1, 8)) {
        [IO.File]::WriteAllText($options, ('{"workers":' + $workers + ',"blockedApplications":["DNS"],"blockedDomains":["example.org"],"blockedIpv4Addresses":["203.0.113.99"]}'))
        & curl.exe --fail-with-body -sS -F 'file=@test_dpi.pcap' -F "options=@$options;type=application/json" -o $second "$base/api/v1/dpi/filter"
        Check ($LASTEXITCODE -eq 0) "Filter with $workers workers failed"
        Check ((Get-FileHash $output).Hash -eq (Get-FileHash $second).Hash) "Output differs with $workers workers"
    }
    & curl.exe --fail-with-body -sS -F 'file=@test_dpi.pcap' -o $second "$base/api/v1/dpi/filter"
    Check ($LASTEXITCODE -eq 0) 'No-rule filter failed'
    Check ((Get-FileHash test_dpi.pcap).Hash -eq (Get-FileHash $second).Hash) 'No-rule filtering changed input bytes'
    $unsupported = Join-Path $work 'unsupported.pcap'
    $bytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'test_dpi.pcap'))
    # Fixture is little-endian classic PCAP; set network/link type to DLT_RAW (101).
    Check ([BitConverter]::ToString($bytes, 0, 4) -eq 'D4-C3-B2-A1') 'Unexpected fixture byte order'
    [Array]::Copy([BitConverter]::GetBytes([uint32]101), 0, $bytes, 20, 4)
    [IO.File]::WriteAllBytes($unsupported, $bytes)
    foreach ($endpoint in @('analyze', 'filter')) {
        $status = & curl.exe -sS -o (Join-Path $work 'error.json') -w '%{http_code}' -F "file=@$unsupported" "$base/api/v1/dpi/$endpoint"
        Check ($LASTEXITCODE -eq 0 -and $status -eq '400') "Unsupported link type: $endpoint returned $status"
    }
    [IO.File]::WriteAllText($options, '{"workers":2.0,"unknown":true}')
    $status = & curl.exe -sS -o (Join-Path $work 'error.json') -w '%{http_code}' -F 'file=@test_dpi.pcap' -F "options=@$options;type=application/json" "$base/api/v1/dpi/analyze"
    Check ($LASTEXITCODE -eq 0 -and $status -eq '400') 'Strict JSON validation failed'
    Write-Host 'PASS: health, Swagger, OpenAPI, 12/8/6/6 analysis, valid 6-packet deterministic download, unsupported link types and strict JSON.'
} finally {
    # Remove only files created in this unique verification directory.
    Get-ChildItem -LiteralPath $work -File | Remove-Item
    Remove-Item -LiteralPath $work
}
