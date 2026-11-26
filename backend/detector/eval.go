package detector

import (
	"slices"
)

// isSuspiciousClass returns true for classifications that represent security alerts
// rather than benign/routine behavior.
func isSuspiciousClass(c Classification) bool {
	switch c {
	case ClassUnexpectedRoleChange, ClassReviewAfterRoleChange, ClassLateralMovementCandidate, ClassRateAnomaly:
		return true
	default:
		return false
	}
}

func isSuspiciousGroundTruth(label string) bool {
	switch label {
	case "unexpected_role_change", "review_after_role_change", "lateral_movement_candidate", "rate_anomaly":
		return true
	default:
		return false
	}
}

// EvaluateAgainstLabels computes Precision, Recall, F1, Median Time to Alert (ms),
// and False Alerts per 1,000 Benign Events without exposing labels to the detector.
func EvaluateAgainstLabels(verdicts []EventVerdict, alerts []Alert, labels map[string]GroundTruthLabel) EvalMetrics {
	m := EvalMetrics{
		TotalEvents: len(verdicts),
	}

	alertByID := make(map[string]Alert, len(alerts))
	for _, a := range alerts {
		alertByID[a.AlertID] = a
	}

	var latenciesMs []float64
	for _, v := range verdicts {
		gt, ok := labels[v.Event.EventID]
		if !ok {
			continue
		}
		gtSusp := isSuspiciousGroundTruth(gt.Label)
		predSusp := isSuspiciousClass(v.Classification)

		if gtSusp {
			m.SuspiciousEvents++
		} else {
			m.BenignEvents++
		}

		switch {
		case gtSusp && predSusp:
			m.TruePositives++
			if a, ok := alertByID[v.AlertID]; ok {
				lat := float64(a.DetectedAtUTC.Sub(v.Event.AdjustedTimeUTC).Milliseconds())
				if lat < 0 {
					lat = 0
				}
				latenciesMs = append(latenciesMs, lat)
			}
		case !gtSusp && predSusp:
			m.FalsePositives++
		case gtSusp && !predSusp:
			m.FalseNegatives++
		}
	}

	if m.TruePositives+m.FalsePositives > 0 {
		m.Precision = float64(m.TruePositives) / float64(m.TruePositives+m.FalsePositives)
	}
	if m.TruePositives+m.FalseNegatives > 0 {
		m.Recall = float64(m.TruePositives) / float64(m.TruePositives+m.FalseNegatives)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	if m.BenignEvents > 0 {
		m.FalseAlertsPer1kBenign = (float64(m.FalsePositives) / float64(m.BenignEvents)) * 1000.0
	}
	m.MedianTimeToAlertMs = medianFloat64(latenciesMs)
	return m
}

func medianFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	cp := slices.Clone(vals)
	slices.Sort(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2.0
}
