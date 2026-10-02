package metrics

// Metrics is a marker interface for all metric backends.
// (Allows future extension: noop, statsd, OTEL, etc.)
type Metrics interface{}
