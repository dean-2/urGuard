package detector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadEventsCSV reads Track-4-Toolkit events.csv in receipt order and normalizes timestamps
// without mutating the original EventTimeUTC or ReceivedTimeUTC fields.
func LoadEventsCSV(path string) ([]NormalizedEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open events csv: %w", err)
	}
	defer f.Close()

	return ParseEventsCSV(f)
}

// ParseEventsCSV parses Track-4-Toolkit CSV rows from an io.Reader.
func ParseEventsCSV(r io.Reader) ([]NormalizedEvent, error) {
	cr := csv.NewReader(r)
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}

	colIdx := make(map[string]int, len(header))
	for i, h := range header {
		colIdx[strings.TrimSpace(h)] = i
	}

	required := []string{
		"event_id", "event_time_utc", "received_time_utc", "source_clock_offset_ms",
		"actor", "source_service", "target_service", "action",
		"role_before", "role_after", "outcome", "approval_id", "session_id", "correlation_id",
	}
	for _, col := range required {
		if _, ok := colIdx[col]; !ok {
			return nil, fmt.Errorf("missing required column %q", col)
		}
	}

	var events []NormalizedEvent
	var seq int64
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read csv row: %w", err)
		}
		seq++

		get := func(col string) string {
			return strings.TrimSpace(rec[colIdx[col]])
		}

		evTime, err := time.Parse(time.RFC3339Nano, get("event_time_utc"))
		if err != nil {
			return nil, fmt.Errorf("event %s event_time_utc: %w", get("event_id"), err)
		}
		rxTime, err := time.Parse(time.RFC3339Nano, get("received_time_utc"))
		if err != nil {
			return nil, fmt.Errorf("event %s received_time_utc: %w", get("event_id"), err)
		}
		offsetMs, err := strconv.ParseInt(get("source_clock_offset_ms"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("event %s source_clock_offset_ms: %w", get("event_id"), err)
		}

		adjusted := evTime.Add(-time.Duration(offsetMs) * time.Millisecond)
		delayMs := rxTime.Sub(adjusted).Milliseconds()

		events = append(events, NormalizedEvent{
			EventID:             get("event_id"),
			EventTimeUTC:        evTime.UTC(),
			ReceivedTimeUTC:     rxTime.UTC(),
			SourceClockOffsetMs: offsetMs,
			AdjustedTimeUTC:     adjusted.UTC(),
			CollectorDelayMs:    delayMs,
			ReceiptSeq:          seq,
			Actor:               get("actor"),
			SourceService:       get("source_service"),
			TargetService:       get("target_service"),
			Action:              get("action"),
			RoleBefore:          get("role_before"),
			RoleAfter:           get("role_after"),
			Outcome:             get("outcome"),
			ApprovalID:          get("approval_id"),
			SessionID:           get("session_id"),
			CorrelationID:       get("correlation_id"),
		})
	}

	return events, nil
}

// LoadApprovalsJSON loads change-control approvals from approvals.json.
func LoadApprovalsJSON(path string) ([]ApprovalRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read approvals json: %w", err)
	}
	var af ApprovalFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("parse approvals json: %w", err)
	}
	return af.Changes, nil
}

// GroundTruthLabel is used ONLY by the evaluation harness (never by detection logic).
type GroundTruthLabel struct {
	EventID string
	Label   string
	Reason  string
}

// LoadLabelsCSV loads labeled ground truth for evaluation metrics only.
func LoadLabelsCSV(path string) (map[string]GroundTruthLabel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open labels csv: %w", err)
	}
	defer f.Close()

	cr := csv.NewReader(f)
	if _, err := cr.Read(); err != nil {
		return nil, fmt.Errorf("read labels header: %w", err)
	}

	labels := make(map[string]GroundTruthLabel)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read label row: %w", err)
		}
		if len(rec) < 3 {
			continue
		}
		id := strings.TrimSpace(rec[0])
		labels[id] = GroundTruthLabel{
			EventID: id,
			Label:   strings.TrimSpace(rec[1]),
			Reason:  strings.TrimSpace(rec[2]),
		}
	}
	return labels, nil
}
