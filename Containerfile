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
HEALTHCHECK --interval=30s --timeout=5s CMD curl -sf http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/server"]
