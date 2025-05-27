# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.24.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o authtransformer ./app

# Runtime stage
FROM alpine:3.19
WORKDIR /app
COPY --from=build /src/authtransformer .
COPY app/config.json ./config.json
EXPOSE 8080
CMD ["./authtransformer"]
