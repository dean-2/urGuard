package detector

import "time"

// Classification represents the deterministic, explainable label assigned to an event.
type Classification string

const (
	ClassRoutine                  Classification = "routine"
	ClassBenignAdmin              Classification = "approved_change"
	ClassRoutineDenial            Classification = "routine_denial"
	ClassIsolatedDenial           Classification = "isolated_denial"
	ClassRoutineDelayed           Classification = "routine_delayed_delivery"
	ClassRoutineClockOffset       Classification = "routine_clock_offset"
	ClassUnexpectedRoleChange     Classification = "unexpected_role_change"
	ClassReviewAfterRoleChange    Classification = "review_after_role_change"
	ClassLateralMovementCandidate Classification = "lateral_movement_candidate"
	ClassRateAnomaly              Classification = "rate_anomaly"
)

// NormalizedEvent is the unified event schema ingested from Track-4-Toolkit CSV/JSON
// and live urGuard canonical audit logs. Raw source timestamps are preserved untouched.
type NormalizedEvent struct {
	EventID             string    `json:"event_id"`
	EventTimeUTC        time.Time `json:"event_time_utc"`
	ReceivedTimeUTC     time.Time `json:"received_time_utc"`
	SourceClockOffsetMs int64     `json:"source_clock_offset_ms"`
	AdjustedTimeUTC     time.Time `json:"adjusted_time_utc"` // EventTimeUTC - SourceClockOffsetMs
	CollectorDelayMs    int64     `json:"collector_delay_ms"`
	ReceiptSeq          int64     `json:"receipt_seq"`

	Actor         string `json:"actor"`
	SourceService string `json:"source_service"`
	TargetService string `json:"target_service"`
	Action        string `json:"action"`
	RoleBefore    string `json:"role_before"`
	RoleAfter     string `json:"role_after"`
	Outcome       string `json:"outcome"`
	ApprovalID    string `json:"approval_id"`
	SessionID     string `json:"session_id"`
	CorrelationID string `json:"correlation_id"`

	// Clock-skew & watermark flags
	LateArrival bool `json:"late_arrival"`
}

// ApprovalRule represents an authorized change-control window from approvals.json.
// ValidUntilUTC is exclusive per the Track 4 specification.
type ApprovalRule struct {
	ApprovalID     string    `json:"approval_id"`
	ApprovedBy     string    `json:"approved_by"`
	Subject        string    `json:"subject"`
	Operation      string    `json:"operation"`
	Role           string    `json:"role"`
	Scope          []string  `json:"scope"`
	ValidFromUTC   time.Time `json:"valid_from_utc"`
	ValidUntilUTC  time.Time `json:"valid_until_utc"`
	EffectiveAtUTC time.Time `json:"effective_at_utc"`
}

// ApprovalFile is the top-level structure of approvals.json.
type ApprovalFile struct {
	Synthetic bool           `json:"synthetic"`
	Changes   []ApprovalRule `json:"changes"`
}

// OrderAlternative records an ambiguous ordering pair when two events fall within
// 2 * max_clock_skew of each other.
type OrderAlternative struct {
	FirstEventID  string `json:"first_event_id"`
	SecondEventID string `json:"second_event_id"`
	DeltaMs       int64  `json:"delta_ms"`
}

// Alert is an explainable detection output with zero AI/ML black-box fields.
type Alert struct {
	AlertID           string             `json:"alert_id"`
	Identity          string             `json:"identity"`
	Classification    Classification     `json:"classification"`
	PathOrRule        string             `json:"path_or_rule"`
	Services          []string           `json:"services"`
	EventIDs          []string           `json:"event_ids"`
	Explanation       string             `json:"explanation"`
	ConfidenceScore   float64            `json:"confidence_score"`
	OrderUncertain    bool               `json:"order_uncertain"`
	PossibleOrderings []OrderAlternative `json:"possible_orderings,omitempty"`
	DetectedAtUTC     time.Time          `json:"detected_at_utc"`
}

// EventVerdict pairs a normalized event with its deterministic classification and rule ID.
type EventVerdict struct {
	Event          NormalizedEvent `json:"event"`
	Classification Classification  `json:"classification"`
	RuleID         string          `json:"rule_id"`
	Reason         string          `json:"reason"`
	AlertID        string          `json:"alert_id,omitempty"`
}

// EvalMetrics summarizes detector performance on labeled synthetic datasets.
type EvalMetrics struct {
	TotalEvents            int     `json:"total_events"`
	BenignEvents           int     `json:"benign_events"`
	SuspiciousEvents       int     `json:"suspicious_events"`
	TruePositives          int     `json:"true_positives"`
	FalsePositives         int     `json:"false_positives"`
	FalseNegatives         int     `json:"false_negatives"`
	Precision              float64 `json:"precision"`
	Recall                 float64 `json:"recall"`
	F1                     float64 `json:"f1"`
	MedianTimeToAlertMs    float64 `json:"median_time_to_alert_ms"`
	FalseAlertsPer1kBenign float64 `json:"false_alerts_per_1k_benign"`
}
