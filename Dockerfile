# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.24.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o authtranslator ./app

# Runtime stage
FROM alpine:3.19
# create non-root group and user for running the application
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build /src/authtranslator .
COPY app/config.yaml ./config.yaml
# ensure the runtime directory is owned by the app user
RUN chown -R app:app /app
USER app
EXPOSE 8080
CMD ["./authtranslator"]
