FROM gradle:8.10.1-jdk21 AS build
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY src ./src
RUN gradle --no-daemon clean installDist

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/build/install/audit-ledger /app/audit-ledger
ENV PORT=8080
ENV LEDGER_DIR=/app/data
EXPOSE 8080
CMD ["/app/audit-ledger/bin/audit-ledger"]
