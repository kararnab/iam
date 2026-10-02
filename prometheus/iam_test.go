package prometheus

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kararnab/iam/v2/metrics"
)

func TestRecorder(t *testing.T) {
	reg := NewRegistry()
	r, err := NewRecorder(reg)
	if err != nil {
		t.Fatal(err)
	}
	r.Inc(metrics.LoginSuccess)
	r.Inc(metrics.LoginSuccess)
	r.Inc(metrics.RefreshReuse)

	tests := []struct {
		event metrics.Event
		want  float64
	}{
		{metrics.LoginSuccess, 2},
		{metrics.RefreshReuse, 1},
		{metrics.PolicyDenied, 0},
	}
	for _, tt := range tests {
		if got := testutil.ToFloat64(r.events.WithLabelValues(string(tt.event))); got != tt.want {
			t.Errorf("%s = %v, want %v", tt.event, got, tt.want)
		}
	}
	if n := testutil.CollectAndCount(r.events); n != len(metrics.Events) {
		t.Errorf("series = %d, want %d (all pre-created)", n, len(metrics.Events))
	}
	if _, err := NewRecorder(reg); err == nil {
		t.Error("double registration accepted")
	}
	var _ prometheus.Registerer = reg
}
