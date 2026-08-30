.PHONY: all build backend frontend run dev test unit integration image up down clean agent agent-test

all: build

backend:
	cd backend && go build -o bin/server ./cmd/server

frontend:
	# `npm ci` wipes node_modules first, which fails on FUSE mounts when an editor holds a
	# .so open (leaves a .fuse_hidden file). `npm install` updates in place; fall back to it.
	cd frontend && (npm ci --no-audit --no-fund || npm install --no-audit --no-fund) && npm run build

build: frontend backend

## Run the API locally, serving the built frontend (needs .env or env vars).
run: build
	set -a; [ -f .env ] && . ./.env; set +a; cd backend && STATIC_DIR=../frontend/dist ./bin/server

## Development: API on :8080 and Vite dev server on :5173 (proxying /api).
dev:
	@echo "Run in two terminals:"
	@echo "  make dev-api"
	@echo "  make dev-web"

dev-api:
	set -a; [ -f .env ] && . ./.env; set +a; cd backend && go run ./cmd/server

dev-web:
	cd frontend && npm run dev

unit:
	cd backend && go test ./...
	cd frontend && npm run check

## Fully automated integration + e2e tests using Podman.
integration:
	scripts/integration-test.sh

test: unit integration

image:
	podman build --format docker -t localhost/pmacct-analyzer:latest -f Containerfile .

up:
	podman compose up -d --build

down:
	podman compose down

## Endpoint agent (Rust). Linux build + Windows cross-build (needs the x86_64-pc-windows-gnu target and mingw-w64).
agent:
	cd agent && cargo build --release
	cd agent && cargo build --release --target x86_64-pc-windows-gnu
	@ls -la agent/target/release/pmacct-agent agent/target/x86_64-pc-windows-gnu/release/pmacct-agent.exe

agent-test:
	cd agent && cargo test

clean:
	rm -rf backend/bin frontend/dist agent/target
