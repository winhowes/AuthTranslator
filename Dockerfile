# syntax=docker/dockerfile:1
FROM alpine:3.19
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY authtranslator .
USER app
EXPOSE 8080
HEALTHCHECK CMD wget -qO- http://localhost:8080/_at_internal/healthz || exit 1
ENTRYPOINT ["./authtranslator"]
