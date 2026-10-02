# Metrics

IAM counts events through a `metrics.Recorder`:

```go
type Recorder interface {
    Inc(e metrics.Event)
}
```

The set of events is fixed and low-cardinality (`metrics.Events`):
`login_success`, `login_failure`, `logout`, `refresh_success`,
`refresh_failure`, `refresh_reuse`, `token_verify_success`,
`token_verify_failure`, `session_revoked`, `policy_denied`, `signup`,
`signup_failure` and `rate_limited`. No subject IDs, tokens or other
unbounded values are ever passed. Adding an event in a later version does
not break your implementation.

The default is `metrics.Noop`.

## Prometheus (`github.com/kararnab/iam/prometheus`)

```go
reg := prometheus.NewRegistry()
rec, err := iamprom.NewRecorder(reg)
cfg.Metrics = rec

http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
```

This exports `iam_events_total{event="..."}`. Every series is created up
front, so `rate()` works from the start. Useful queries:

```promql
rate(iam_events_total{event="login_failure"}[5m])
increase(iam_events_total{event="refresh_reuse"}[1h]) > 0
```

Serve `/metrics` on a private listener. The demo binds it to
`127.0.0.1:9090`.

## Other backends

Implement `Inc` for OpenTelemetry, StatsD, or anything else. Keep it
non-blocking.
