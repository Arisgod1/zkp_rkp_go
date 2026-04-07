package audit

import "time"

type EventType string

const (
	EventRegister  EventType = "auth.register"
	EventChallenge EventType = "auth.challenge"
	EventVerify    EventType = "auth.verify"
)

type Event struct {
	EventID     string    `json:"event_id"`
	EventType   EventType `json:"event_type"`
	Username    string    `json:"username,omitempty"`
	Success     bool      `json:"success"`
	Reason      string    `json:"reason,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	ChallengeID string    `json:"challenge_id,omitempty"`
	OccurredAt  time.Time `json:"occurred_at"`
}
