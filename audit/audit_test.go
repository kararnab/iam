package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSlogLogger(t *testing.T) {
	tests := []struct {
		name      string
		event     Event
		wantLevel string
		wantParts []string
	}{
		{"login", Event{Type: EventLoginSuccess, SubjectID: "s1", SessionID: "sess", ClientIP: "203.0.113.1", Message: "ok"},
			"INFO", []string{"event_type=login_success", "subject_id=s1", "session_id=sess", "client_ip=203.0.113.1"}},
		{"reuse is a warning", Event{Type: EventRefreshReuse, Attrs: map[string]string{"reason": "reuse"}},
			"WARN", []string{"event_type=refresh_reuse_detected", "attrs.reason=reuse"}},
		{"lockout is a warning", Event{Type: EventLockout}, "WARN", []string{"event_type=lockout"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := NewSlogLogger(slog.New(slog.NewTextHandler(&buf, nil)))
			tt.event.Time = time.Unix(1_800_000_000, 0)
			if err := l.Log(context.Background(), tt.event); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			if !strings.Contains(out, "level="+tt.wantLevel) {
				t.Fatalf("level missing in %q", out)
			}
			for _, p := range tt.wantParts {
				if !strings.Contains(out, p) {
					t.Fatalf("%q missing in %q", p, out)
				}
			}
		})
	}
}

func TestMulti(t *testing.T) {
	var got []EventType
	rec := Func(func(_ context.Context, e Event) error { got = append(got, e.Type); return nil })
	boom := errors.New("boom")
	failing := Func(func(context.Context, Event) error { return boom })

	err := Multi(rec, failing, rec).Log(context.Background(), Event{Type: EventLogout})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("delivered to %d of 2 working loggers", len(got))
	}
}
