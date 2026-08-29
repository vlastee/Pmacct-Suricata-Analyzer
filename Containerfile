# ---- frontend build ----
FROM docker.io/library/node:24-alpine AS frontend
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- backend build ----
FROM docker.io/library/golang:1.26-alpine AS backend
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ---- runtime ----
FROM docker.io/library/alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl && adduser -D -u 10001 app
WORKDIR /app
COPY --from=backend /out/server /app/server
COPY --from=frontend /app/dist /app/static
ENV STATIC_DIR=/app/static LISTEN_ADDR=:8080
USER app
EXPOSE 8080
# Derive the port from LISTEN_ADDR at runtime so a custom port still passes the health check.
# Dockerfiles do not expand variables in HEALTHCHECK, so ${...} reaches the container shell as-is;
# do NOT escape the $ — "\$" would make the shell pass the literal text "${LISTEN_ADDR##*:}" to curl.
HEALTHCHECK --interval=30s --timeout=5s CMD curl -sf "http://127.0.0.1:${LISTEN_ADDR##*:}/healthz" || exit 1
ENTRYPOINT ["/app/server"]
