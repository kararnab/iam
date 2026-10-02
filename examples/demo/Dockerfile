# Build from the repository root (the demo uses replace directives to ../..):
#   docker build -f examples/demo/Dockerfile -t kararnab/iam-demo .

# ---- Build stage ----
FROM golang:1.27-alpine AS builder

WORKDIR /src

# Copy the library and its sub-modules, then the demo.
COPY . .

WORKDIR /src/examples/demo
RUN go mod download

# Build a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/iam-demo .

# ---- Runtime stage ----
FROM gcr.io/distroless/static-debian12

COPY --from=builder /out/iam-demo /app/iam-demo

# Run as non-root
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/iam-demo"]
