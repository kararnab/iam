package audit

import (
	"context"
	"log/slog"
)

// SlogLogger writes audit events to a log/slog logger.
//
// Event attributes are written as a group. Callers must never put secrets
// (tokens, passwords, session secrets) into an Event.
type SlogLogger struct {
	// Logger receives the events. Nil means slog.Default().
	Logger *slog.Logger
}

// NewSlogLogger returns an audit logger that writes to l (nil means slog.Default()).
func NewSlogLogger(l *slog.Logger) *SlogLogger {
	return &SlogLogger{Logger: l}
}

// Log implements Logger.
func (s *SlogLogger) Log(ctx context.Context, event Event) error {
	l := s.Logger
	if l == nil {
		l = slog.Default()
	}

	attrs := make([]any, 0, len(event.Attrs))
	for k, v := range event.Attrs {
		attrs = append(attrs, slog.String(k, v))
	}

	level := slog.LevelInfo
	switch event.Type {
	case EventRefreshReuse, EventLockout:
		level = slog.LevelWarn
	}

	l.LogAttrs(ctx, level, event.Message,
		slog.String("log_type", "audit"),
		slog.String("event_type", string(event.Type)),
		slog.Time("event_time", event.Time),
		slog.String("subject_id", event.SubjectID),
		slog.String("session_id", event.SessionID),
		slog.String("provider", event.Provider),
		slog.String("client_ip", event.ClientIP),
		slog.Group("attrs", attrs...),
	)
	return nil
}
