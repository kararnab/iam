package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
)

// NewRegistry creates a Prometheus registry.
//
// Separate registry prevents global pollution.
func NewRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}
