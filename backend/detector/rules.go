package detector

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// RuleEngine evaluates deterministic policy, approval-context, and EWMA rate rules.
// It uses zero AI/ML and emits human-readable rule IDs and explanations.
type RuleEngine struct {
	approvalsByID       map[string]ApprovalRule
	taintedSessions     map[string]string // session_id -> triggering event_id
	ewmaRateByActor     map[string]float64
	sampleCountByActor  map[string]int
	lastEventTimeActor  map[string]time.Time
	ewmaAlpha           float64
	rateSpikeMultiplier float64
	minBaselineSamples  int
	minBurstRatePerSec  float64
}

// NewRuleEngine initializes the deterministic rule engine with change-control approvals.
func NewRuleEngine(approvals []ApprovalRule) *RuleEngine {
	byID := make(map[string]ApprovalRule, len(approvals))
	for _, a := range approvals {
		byID[a.ApprovalID] = a
	}
	return &RuleEngine{
		approvalsByID:       byID,
		taintedSessions:     make(map[string]string),
		ewmaRateByActor:     make(map[string]float64),
		sampleCountByActor:  make(map[string]int),
		lastEventTimeActor:  make(map[string]time.Time),
		ewmaAlpha:           0.3,
		rateSpikeMultiplier: 5.0,
		minBaselineSamples:  5,
		minBurstRatePerSec:  2.0,
	}
}

// Evaluate applies context-aware rules to a single event (after watermark ordering).
func (re *RuleEngine) Evaluate(ev NormalizedEvent) (EventVerdict, *Alert) {
	rateSpike, instRate, baselineRate := re.updateEWMA(ev)

	// 1. Role administration & escalation checks.
	if ev.Action == "approve_role_change" || ev.Action == "revoke_role" {
		if re.isValidAdminAction(ev) {
			return EventVerdict{
				Event:          ev,
				Classification: ClassBenignAdmin,
				RuleID:         "RULE_APPROVED_CHANGE_ADMIN",
				Reason:         fmt.Sprintf("Authorized admin operation %s under %s", ev.Action, ev.ApprovalID),
			}, nil
		}
		alert := &Alert{
			AlertID:         "alert-" + ev.EventID,
			Identity:        ev.Actor,
			Classification:  ClassUnexpectedRoleChange,
			PathOrRule:      "RULE_UNAPPROVED_ADMIN_OP",
			Services:        []string{ev.SourceService, ev.TargetService},
			EventIDs:        []string{ev.EventID},
			Explanation:     fmt.Sprintf("Admin operation %s by %s lacks valid approval %q", ev.Action, ev.Actor, ev.ApprovalID),
			ConfidenceScore: 0.90,
			DetectedAtUTC:   ev.ReceivedTimeUTC,
		}
		return EventVerdict{
			Event:          ev,
			Classification: ClassUnexpectedRoleChange,
			RuleID:         alert.PathOrRule,
			Reason:         alert.Explanation,
			AlertID:        alert.AlertID,
		}, alert
	}

	if ev.Action == "role_change" || ev.RoleBefore != ev.RoleAfter {
		if re.isApprovedRoleChange(ev) {
			return EventVerdict{
				Event:          ev,
				Classification: ClassBenignAdmin,
				RuleID:         "RULE_APPROVED_ROLE_CHANGE",
				Reason:         fmt.Sprintf("Role change %s->%s matches approval %s", ev.RoleBefore, ev.RoleAfter, ev.ApprovalID),
			}, nil
		}

		// Unexpected / unapproved role escalation.
		if ev.SessionID != "" {
			re.taintedSessions[ev.SessionID] = ev.EventID
		}
		alert := &Alert{
			AlertID:         "alert-" + ev.EventID,
			Identity:        ev.Actor,
			Classification:  ClassUnexpectedRoleChange,
			PathOrRule:      "RULE_UNEXPECTED_ROLE_CHANGE",
			Services:        []string{ev.SourceService, ev.TargetService},
			EventIDs:        []string{ev.EventID},
			Explanation:     fmt.Sprintf("Actor %s changed role %s -> %s with no valid approval (approval_id=%q)", ev.Actor, ev.RoleBefore, ev.RoleAfter, ev.ApprovalID),
			ConfidenceScore: 0.95,
			DetectedAtUTC:   ev.ReceivedTimeUTC,
		}
		return EventVerdict{
			Event:          ev,
			Classification: ClassUnexpectedRoleChange,
			RuleID:         alert.PathOrRule,
			Reason:         alert.Explanation,
			AlertID:        alert.AlertID,
		}, alert
	}

	// 2. Post-escalation activity in a session with an unexpected role change.
	if ev.SessionID != "" {
		if triggerID, tainted := re.taintedSessions[ev.SessionID]; tainted && ev.Outcome == "allow" {
			alert := &Alert{
				AlertID:         "alert-" + ev.EventID,
				Identity:        ev.Actor,
				Classification:  ClassReviewAfterRoleChange,
				PathOrRule:      "RULE_ACCESS_AFTER_UNEXPECTED_ROLE_CHANGE",
				Services:        []string{ev.SourceService, ev.TargetService},
				EventIDs:        []string{triggerID, ev.EventID},
				Explanation:     fmt.Sprintf("Allowed %s on %s in session %s following unapproved role change %s", ev.Action, ev.TargetService, ev.SessionID, triggerID),
				ConfidenceScore: 0.85,
				DetectedAtUTC:   ev.ReceivedTimeUTC,
			}
			return EventVerdict{
				Event:          ev,
				Classification: ClassReviewAfterRoleChange,
				RuleID:         alert.PathOrRule,
				Reason:         alert.Explanation,
				AlertID:        alert.AlertID,
			}, alert
		}
	}

	// 3. Routine revocation-related denials vs. isolated denials.
	if ev.Outcome == "deny" {
		if ev.ApprovalID != "" {
			if rule, ok := re.approvalsByID[ev.ApprovalID]; ok && rule.Operation == "revoke_role" {
				return EventVerdict{
					Event:          ev,
					Classification: ClassRoutineDenial,
					RuleID:         "RULE_POST_REVOCATION_DENIAL",
					Reason:         fmt.Sprintf("Access to %s denied after revocation %s", ev.TargetService, ev.ApprovalID),
				}, nil
			}
		}
		return EventVerdict{
			Event:          ev,
			Classification: ClassIsolatedDenial,
			RuleID:         "RULE_ISOLATED_DENIAL",
			Reason:         fmt.Sprintf("Single denied %s to %s (insufficient alone for lateral movement)", ev.Action, ev.TargetService),
		}, nil
	}

	// 4. EWMA rate-spike anomaly check (only after sufficient baseline samples).
	if rateSpike {
		alert := &Alert{
			AlertID:         "alert-rate-" + ev.EventID,
			Identity:        ev.Actor,
			Classification:  ClassRateAnomaly,
			PathOrRule:      "RULE_EWMA_RATE_SPIKE",
			Services:        []string{ev.SourceService, ev.TargetService},
			EventIDs:        []string{ev.EventID},
			Explanation:     fmt.Sprintf("Actor %s request rate %.2f/s exceeded %.1fx EWMA baseline (%.2f/s)", ev.Actor, instRate, re.rateSpikeMultiplier, baselineRate),
			ConfidenceScore: 0.88,
			DetectedAtUTC:   ev.ReceivedTimeUTC,
		}
		return EventVerdict{
			Event:          ev,
			Classification: ClassRateAnomaly,
			RuleID:         alert.PathOrRule,
			Reason:         alert.Explanation,
			AlertID:        alert.AlertID,
		}, alert
	}

	// 5. Clock offset / delayed delivery observability (routine unless paired with rule violations).
	if ev.SourceClockOffsetMs != 0 {
		return EventVerdict{
			Event:          ev,
			Classification: ClassRoutineClockOffset,
			RuleID:         "RULE_CLOCK_OFFSET_NORMALIZED",
			Reason:         fmt.Sprintf("Source clock offset %dms subtracted; collector delay %dms", ev.SourceClockOffsetMs, ev.CollectorDelayMs),
		}, nil
	}

	return EventVerdict{
		Event:          ev,
		Classification: ClassRoutine,
		RuleID:         "RULE_ROUTINE_ACCESS",
		Reason:         fmt.Sprintf("Normal %s on %s as %s", ev.Action, ev.TargetService, ev.RoleAfter),
	}, nil
}

func (re *RuleEngine) isValidAdminAction(ev NormalizedEvent) bool {
	rule, ok := re.approvalsByID[ev.ApprovalID]
	if !ok {
		return false
	}
	if rule.ApprovedBy != "" && rule.ApprovedBy != ev.Actor {
		return false
	}
	return true
}

func (re *RuleEngine) isApprovedRoleChange(ev NormalizedEvent) bool {
	if ev.ApprovalID == "" {
		return false
	}
	rule, ok := re.approvalsByID[ev.ApprovalID]
	if !ok || rule.Operation != "grant_role" {
		return false
	}
	if rule.Subject != ev.Actor || rule.Role != ev.RoleAfter {
		return false
	}
	// ValidUntilUTC is exclusive per Track 4 specification.
	t := ev.AdjustedTimeUTC
	if !rule.ValidFromUTC.IsZero() && t.Before(rule.ValidFromUTC) {
		return false
	}
	if !rule.ValidUntilUTC.IsZero() && !t.Before(rule.ValidUntilUTC) {
		return false
	}
	return true
}

// IsWithinApprovedScope checks whether an access event falls within an approval's scope and window.
func (re *RuleEngine) IsWithinApprovedScope(ev NormalizedEvent) bool {
	if ev.ApprovalID == "" {
		return false
	}
	rule, ok := re.approvalsByID[ev.ApprovalID]
	if !ok {
		return false
	}
	if len(rule.Scope) > 0 && !slices.Contains(rule.Scope, ev.TargetService) {
		return false
	}
	t := ev.AdjustedTimeUTC
	if !rule.ValidFromUTC.IsZero() && t.Before(rule.ValidFromUTC) {
		return false
	}
	if !rule.ValidUntilUTC.IsZero() && !t.Before(rule.ValidUntilUTC) {
		return false
	}
	return true
}

func (re *RuleEngine) updateEWMA(ev NormalizedEvent) (bool, float64, float64) {
	re.sampleCountByActor[ev.Actor]++
	prev, ok := re.lastEventTimeActor[ev.Actor]
	re.lastEventTimeActor[ev.Actor] = ev.AdjustedTimeUTC
	if !ok {
		return false, 0, 0
	}
	dt := ev.AdjustedTimeUTC.Sub(prev).Seconds()
	if dt <= 0.001 {
		dt = 0.001
	}
	instRate := 1.0 / dt
	oldEWMA := re.ewmaRateByActor[ev.Actor]
	if oldEWMA == 0 {
		re.ewmaRateByActor[ev.Actor] = instRate
		return false, instRate, 0
	}
	spike := re.sampleCountByActor[ev.Actor] >= re.minBaselineSamples &&
		instRate >= re.minBurstRatePerSec &&
		instRate > oldEWMA*re.rateSpikeMultiplier
	re.ewmaRateByActor[ev.Actor] = re.ewmaAlpha*instRate + (1-re.ewmaAlpha)*oldEWMA
	_ = math.Abs(instRate - oldEWMA)
	return spike, instRate, oldEWMA
}
