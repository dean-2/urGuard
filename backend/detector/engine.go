package detector

import (
	"fmt"
	"time"
)

// Detector orchestrates the watermark buffer, deterministic rule engine, and
// lateral-movement access graph.
type Detector struct {
	Watermark *WatermarkBuffer
	Rules     *RuleEngine
	Graph     *AccessGraph
}

// NewDetector constructs an explainable detector with configurable clock-skew window.
func NewDetector(maxClockSkew time.Duration, approvals []ApprovalRule) *Detector {
	return &Detector{
		Watermark: NewWatermarkBuffer(maxClockSkew),
		Rules:     NewRuleEngine(approvals),
		Graph:     NewAccessGraph(5*time.Minute, 2),
	}
}

// ProcessBatch ingests events in receipt order, orders them through the bounded
// watermark buffer, evaluates rules & graph transitions, and returns verdicts + alerts.
func (d *Detector) ProcessBatch(events []NormalizedEvent) ([]EventVerdict, []Alert) {
	var ordered []NormalizedEvent
	for _, ev := range events {
		ready := d.Watermark.Push(ev)
		ordered = append(ordered, ready...)
	}
	ordered = append(ordered, d.Watermark.Flush()...)

	// Detect pairs whose timestamps fall within 2 * MaxClockSkew.
	uncertain, alts := d.Watermark.DetectOrderUncertainty(ordered)
	uncertainByEvent := make(map[string][]OrderAlternative)
	if uncertain {
		for _, alt := range alts {
			uncertainByEvent[alt.FirstEventID] = append(uncertainByEvent[alt.FirstEventID], alt)
			uncertainByEvent[alt.SecondEventID] = append(uncertainByEvent[alt.SecondEventID], alt)
		}
	}

	// Track receipt-order vs causal-order inversions (e.g., evt-014 arriving before evt-013).
	maxSeqSeen := int64(0)
	delayedIDs := make(map[string]bool)
	for _, ev := range ordered {
		// If an event with an earlier AdjustedTimeUTC had a higher ReceiptSeq than a
		// previously seen later event, it arrived delayed.
		if ev.ReceiptSeq < maxSeqSeen {
			// Earlier receipt came after; handled on the higher-seq item below.
		} else {
			maxSeqSeen = ev.ReceiptSeq
		}
	}
	// Check inversions in receipt order vs adjusted time.
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].AdjustedTimeUTC.Before(events[i].AdjustedTimeUTC) {
				delayedIDs[events[j].EventID] = true
			}
		}
	}

	verdicts := make([]EventVerdict, 0, len(ordered))
	var alerts []Alert
	verdictIdxByID := make(map[string]int, len(ordered))

	for _, ev := range ordered {
		v, ruleAlert := d.Rules.Evaluate(ev)
		if delayedIDs[ev.EventID] && v.Classification == ClassRoutine {
			v.Classification = ClassRoutineDelayed
			v.RuleID = "RULE_DELAYED_DELIVERY"
			v.Reason = fmt.Sprintf("Event %s arrived out of order (receipt_seq=%d)", ev.EventID, ev.ReceiptSeq)
		}

		if ruleAlert != nil {
			if pairs, ok := uncertainByEvent[ev.EventID]; ok {
				ruleAlert.OrderUncertain = true
				ruleAlert.PossibleOrderings = pairs
			}
			alerts = append(alerts, *ruleAlert)
		}

		if v.Classification != ClassRoutineDenial {
			if graphAlert := d.Graph.Observe(ev, d.Watermark); graphAlert != nil {
				if pairs, ok := uncertainByEvent[ev.EventID]; ok {
					graphAlert.OrderUncertain = true
					graphAlert.PossibleOrderings = pairs
				}
				alerts = append(alerts, *graphAlert)

				// Retroactively mark all events in the multi-hop sequence as lateral_movement_candidate.
				for _, eid := range graphAlert.EventIDs {
					if idx, ok := verdictIdxByID[eid]; ok {
						verdicts[idx].Classification = ClassLateralMovementCandidate
						verdicts[idx].RuleID = graphAlert.PathOrRule
						verdicts[idx].AlertID = graphAlert.AlertID
					}
				}
				v.Classification = ClassLateralMovementCandidate
				v.RuleID = graphAlert.PathOrRule
				v.Reason = graphAlert.Explanation
				v.AlertID = graphAlert.AlertID
			}
		}

		verdictIdxByID[ev.EventID] = len(verdicts)
		verdicts = append(verdicts, v)
	}

	return verdicts, alerts
}
