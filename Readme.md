Role Based Authentication System (Go)
====================================

A role-based authentication demo written in Go with minimal dependencies.

---

## Project Overview

This project demonstrates:
- Role-based authentication
- Clean Go project layout (`cmd/`, `internal/`, `pkg/`)
- Containerized deployment using Docker
- Environment-based configuration

This version replaces the earlier Node.js implementation (See tag: `v1.0-nodejs`).

---

> **Work in progress:** this repository is being turned into the importable
> library `github.com/kararnab/iam`. See `docs/plan-reusable-iam.md`.
> The demo app now lives in `examples/demo`.

## API Documentation
- Hoppscotch collection: `examples/demo/hoppscotch.json`
- OpenAPI spec: `examples/demo/openapi.yaml`

## Requirements

- Go 1.26+
- Docker (optional)

## Running the demo locally

```bash
cd examples/demo
go run .
```

The API listens on `:8080` (`PORT`). Prometheus metrics are served on
`127.0.0.1:9090/metrics` (`ADMIN_ADDR`), not on the public port.

## Running the demo with Docker

```bash
docker build -f examples/demo/Dockerfile -t kararnab/iam-demo .
docker run -p 8080:8080 --env-file .env kararnab/iam-demo
```

Copy `.env.example` to `.env` first.

## Tests

```bash
./scripts/each-module.sh go test -race ./...
```
