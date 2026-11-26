package detector

import (
	"fmt"
	"time"
)

// AuditEvent mirrors Engineer A's canonical tamper-evident audit log record.
// User-supplied Metadata is isolated and never parsed as control fields.
type AuditEvent struct {
	Seq                 int64             `json:"seq"`
	EventID             string            `json:"event_id"`
	EventTimeUTC        time.Time         `json:"event_time_utc"`
	ReceivedTimeUTC     time.Time         `json:"received_time_utc"`
	SourceClockOffsetMs int64             `json:"source_clock_offset_ms"`
	ActorID             string            `json:"actor_id"`
	SourceService       string            `json:"source_service"`
	TargetService       string            `json:"target_service"`
	Action              string            `json:"action"`
	RoleBefore          string            `json:"role_before"`
	RoleAfter           string            `json:"role_after"`
	Outcome             string            `json:"outcome"`
	ApprovalID          string            `json:"approval_id"`
	SessionID           string            `json:"session_id"`
	CorrelationID       string            `json:"correlation_id"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// NormalizeAuditEvent converts a canonical urGuard AuditEvent into a NormalizedEvent
// without mutating source timestamps or trusting Metadata strings as control fields.
func NormalizeAuditEvent(a AuditEvent, receiptSeq int64) NormalizedEvent {
	evTime := a.EventTimeUTC.UTC()
	rxTime := a.ReceivedTimeUTC.UTC()
	if rxTime.IsZero() {
		rxTime = evTime
	}
	adjusted := evTime.Add(-time.Duration(a.SourceClockOffsetMs) * time.Millisecond)
	delayMs := rxTime.Sub(adjusted).Milliseconds()

	evID := a.EventID
	if evID == "" {
		evID = fmt.Sprintf("audit-%d", a.Seq)
	}

	return NormalizedEvent{
		EventID:             evID,
		EventTimeUTC:        evTime,
		ReceivedTimeUTC:     rxTime,
		SourceClockOffsetMs: a.SourceClockOffsetMs,
		AdjustedTimeUTC:     adjusted.UTC(),
		CollectorDelayMs:    delayMs,
		ReceiptSeq:          receiptSeq,
		Actor:               a.ActorID,
		SourceService:       a.SourceService,
		TargetService:       a.TargetService,
		Action:              a.Action,
		RoleBefore:          a.RoleBefore,
		RoleAfter:           a.RoleAfter,
		Outcome:             a.Outcome,
		ApprovalID:          a.ApprovalID,
		SessionID:           a.SessionID,
		CorrelationID:       a.CorrelationID,
	}
}
