# Build the Narthex engine (cmd/engine) — MCP gateway + OAuth AS + console API.
# Requires Go >= 1.25.5 (mcp-go).
FROM golang:1.25-bookworm AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /engine ./cmd/engine
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /healthcheck ./cmd/healthcheck

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /engine /engine
COPY --from=build /healthcheck /healthcheck
EXPOSE 8080
ENTRYPOINT ["/engine"]
