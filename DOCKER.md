# Docker deployment

Requires Docker Desktop with Linux containers and Compose. Host Java/Maven are unnecessary. First build requires internet access for images and Maven Central. Image: `dpi-engine-api:phase11`.

## Consolidated PowerShell verification checklist

```powershell
Set-Location D:\Projects\Packet_analyzer
docker version
docker compose config
docker compose build
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
docker compose up -d
docker compose logs --tail 100 dpi-api
powershell -NoProfile -ExecutionPolicy Bypass -File .\docker-verify.ps1
if ($LASTEXITCODE -ne 0) { throw 'API verification failed' }
docker compose exec -T dpi-api id
docker compose exec -T dpi-api sh -c 'find /tmp/dpi-engine-api -mindepth 1 -print'
docker compose stats --no-stream
docker compose stop
docker compose ps -a
docker compose logs --tail 50 dpi-api
docker compose down
```

Expected: 344 core + 79 API tests pass during build. Verification reports PASS for health, Swagger/OpenAPI, demo analysis (12 packets, 8 flows, 6 allowed, 6 blocked), download headers, re-analysis of the valid 6-packet download, identical repeated output, HTTP 400 for unsupported link types on both endpoints, and strict JSON validation. The script requires Windows `curl.exe`, creates its own invalid-link fixture and removes its temporary files. It does not start or stop containers.

UID/GID must be 10001. After requests, the workspace `find` should print nothing. Stop should show orderly Spring shutdown without cleanup errors; `down` removes containers and temporary storage. Follow logs with `docker compose logs -f dpi-api`. View Swagger at <http://localhost:8080/swagger-ui/index.html> and OpenAPI at <http://localhost:8080/v3/api-docs> while running. Stop any host API already using port 8080.

Individual multipart requests:

```powershell
'{"workers":4,"blockedApplications":["DNS"],"blockedDomains":["example.org"],"blockedIpv4Addresses":["203.0.113.99"]}' | Set-Content -Encoding ascii demo-options.json
curl.exe --fail-with-body -F 'file=@test_dpi.pcap' -F 'options=@demo-options.json;type=application/json' http://localhost:8080/api/v1/dpi/analyze
curl.exe --fail-with-body -D filter-headers.txt -F 'file=@test_dpi.pcap' -F 'options=@demo-options.json;type=application/json' -o docker-filtered.pcap http://localhost:8080/api/v1/dpi/filter
```

Omitted options mean no rules (12 allowed), as before. Standalone build: `docker build -t dpi-engine-api:phase11 .`. Prefer Compose for startup because it supplies port publication and runtime restrictions.

## Configuration and limits

The image overrides the existing local-development address through `SERVER_ADDRESS=0.0.0.0` and `SERVER_PORT=8080`; application.properties retains its local default. Compose publishes `127.0.0.1:8080:8080`, keeping host access local. `EXPOSE` alone does not publish a port.

All existing `DPI_*` variables/defaults in [the API README](dpi-engine-api/README.md) remain supported. Add overrides under Compose `environment` and recreate with `docker compose up -d`. Host variables are not automatically forwarded. `DPI_TEMP_DIRECTORY=/tmp/dpi-engine-api` stays within writable storage. Any alternative mount requires UID 10001 write permissions. Java/Tomcat temporary files and multipart spooling also use `/tmp`.

`JAVA_TOOL_OPTIONS` sets 64 MiB initial/512 MiB maximum heap and two active processors. Compose limits memory to 1 GiB, CPU to two, and processes/threads to 256. The 256 MiB `/tmp` tmpfs consumes container/VM memory on demand, shared by uploads, workspaces and downloads. The rest of the filesystem is read-only; all capabilities are dropped and privilege escalation is disabled. The non-root user can create, stream and delete its workspaces. Normal cleanup remains unchanged; tmpfs disappears on stop, including crash leftovers. No persistent volume is necessary.

Provision Docker VM memory for JVM native memory, tmpfs and Docker overhead as well as the Java heap. Build sequentially without Maven `-T`, preferably while the service is stopped; the build JVM and test forks each have a 512 MiB heap cap. Processing/upload/worker budgets remain unchanged. Tmpfs exhaustion can produce I/O errors; memory exhaustion can kill the container. Raising API limits requires reassessing heap, native memory, tmpfs and VM capacity. No automatic restart policy or request deadline is added.

## Build structure

The root multi-stage build runs `mvn clean verify` for both modules with the root `test_dpi.pcap` fixture and copies only the executable Spring Boot JAR into a Java 21 Alpine JRE image. No sources, test fixtures, Maven cache or host credentials enter the final image. BuildKit caches Maven downloads across source edits and reuses unchanged build layers. The allowlist `.dockerignore` excludes targets, bin/IDE files, Git metadata, non-build inputs, secrets, logs and generated captures. New inputs outside the two `src` trees must be explicitly allowed and copied.

Base images are pinned by digest; refresh pins deliberately for security updates. Maven versions remain those in existing POMs, including the reactor's SNAPSHOT version. This does not promise bit-for-bit JAR output or an offline first build. Official image references: [Maven](https://hub.docker.com/_/maven/), [Eclipse Temurin](https://hub.docker.com/_/eclipse-temurin/).

## Verification status

The current fixture has 12 records and 8 directional flows; example rules allow 6 and block 6. The script checks no-rule byte equality and identical filtered output with 1, 4 and 8 workers. The Docker Linux engine was unavailable for the final preparation run, so a current container verification result is not claimed. See [fixture details](docs/FIXTURE.md) and the [verification guide](dpi-engine-api/VERIFICATION.md).
