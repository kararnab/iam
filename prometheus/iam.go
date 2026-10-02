// Package prometheus exports IAM metrics to Prometheus.
package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/kararnab/iam/metrics"
)

const (
	namespace = "iam"
)

// Recorder implements metrics.Recorder with one counter vector,
// iam_events_total{event="..."}. The label set is fixed (metrics.Events),
// so cardinality stays bounded.
type Recorder struct {
	events *prometheus.CounterVec
}

var _ metrics.Recorder = (*Recorder)(nil)

// NewRecorder creates the counters and registers them with reg.
func NewRecorder(reg prometheus.Registerer) (*Recorder, error) {
	vec := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "events_total",
		Help:      "Security-relevant IAM events by type.",
	}, []string{"event"})
	if err := reg.Register(vec); err != nil {
		return nil, err
	}
	// Pre-create every series so rates are defined from the start.
	for _, e := range metrics.Events {
		vec.WithLabelValues(string(e))
	}
	return &Recorder{events: vec}, nil
}

// Inc implements metrics.Recorder.
func (r *Recorder) Inc(e metrics.Event) { r.events.WithLabelValues(string(e)).Inc() }
