# syntax=docker/dockerfile:1
FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
WORKDIR /build
ENV MAVEN_OPTS="-Xmx512m"
COPY pom.xml ./
COPY dpi-engine-java/pom.xml dpi-engine-java/pom.xml
COPY dpi-engine-api/pom.xml dpi-engine-api/pom.xml
# Cache Maven downloads, including reactor dependencies resolved during verify.
COPY dpi-engine-java/src dpi-engine-java/src
COPY dpi-engine-api/src dpi-engine-api/src
COPY test_dpi.pcap ./
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp -DargLine=-Xmx512m clean verify

FROM eclipse-temurin:21-jre-alpine@sha256:51ab5e3302e7141ce665ca3ea85e8b5cd648eafbc3c0c90dd79d6537684e4555 AS runtime
RUN addgroup -S -g 10001 dpi && adduser -S -D -H -u 10001 -G dpi dpi
WORKDIR /app
COPY --from=build --chown=10001:10001 /build/dpi-engine-api/target/dpi-engine-api-1.0-SNAPSHOT.jar /app/app.jar
ENV SERVER_ADDRESS=0.0.0.0 \
    SERVER_PORT=8080 \
    DPI_TEMP_DIRECTORY=/tmp/dpi-engine-api \
    JAVA_TOOL_OPTIONS="-Xms64m -Xmx512m -XX:ActiveProcessorCount=2 -Djava.io.tmpdir=/tmp"
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
