package capacity

import "time"

type HTTPBudgets struct {
	PublicRead, PublicWrite, InternalRead, InternalWrite time.Duration
}

// HTTPTimeouts is operator-only. Request documents cannot change these bounds.
// WriteTimeout is a connection deadline, not proof a complete run met its SLA.
func HTTPTimeouts(resourceProfile string) (HTTPBudgets, error) {
	if _, err := ArtifactBytes(resourceProfile); err != nil {
		return HTTPBudgets{}, err
	}
	b := HTTPBudgets{PublicRead: 30 * time.Second, PublicWrite: 60 * time.Second, InternalRead: 15 * time.Second, InternalWrite: 30 * time.Second}
	switch resourceProfile {
	case DevelopmentS100:
		b.PublicWrite = 180 * time.Second
		b.InternalWrite = 180 * time.Second
	case Engineering:
		b.PublicRead = 60 * time.Second
		b.InternalRead = 60 * time.Second
		b.PublicWrite = 600 * time.Second
		b.InternalWrite = 600 * time.Second
	}
	return b, nil
}
