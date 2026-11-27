package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dean-2/urGuard/backend/detector"
)

func main() {
	eventsPath := flag.String("events", "detector/testdata/events.csv", "Path to events CSV")
	approvalsPath := flag.String("approvals", "detector/testdata/approvals.json", "Path to approvals JSON")
	labelsPath := flag.String("labels", "detector/testdata/labels.csv", "Path to ground-truth labels CSV (evaluation only)")
	skew := flag.Duration("skew", 30*time.Second, "Max clock skew watermark window")
	jsonOut := flag.Bool("json", false, "Output metrics and alerts as JSON")
	flag.Parse()

	events, err := detector.LoadEventsCSV(*eventsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading events: %v\n", err)
		os.Exit(1)
	}
	approvals, err := detector.LoadApprovalsJSON(*approvalsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading approvals: %v\n", err)
		os.Exit(1)
	}
	labels, err := detector.LoadLabelsCSV(*labelsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading labels: %v\n", err)
		os.Exit(1)
	}

	det := detector.NewDetector(*skew, approvals)
	verdicts, alerts := det.ProcessBatch(events)
	metrics := detector.EvaluateAgainstLabels(verdicts, alerts, labels)

	if *jsonOut {
		out := struct {
			SkewSeconds float64              `json:"max_clock_skew_sec"`
			Metrics     detector.EvalMetrics `json:"metrics"`
			Alerts      []detector.Alert     `json:"alerts"`
		}{
			SkewSeconds: skew.Seconds(),
			Metrics:     metrics,
			Alerts:      alerts,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("urGuard Detector Evaluation (max_clock_skew=%v)\n", *skew)
	fmt.Printf("  Total Events:              %d (benign=%d, suspicious=%d)\n", metrics.TotalEvents, metrics.BenignEvents, metrics.SuspiciousEvents)
	fmt.Printf("  TP / FP / FN:              %d / %d / %d\n", metrics.TruePositives, metrics.FalsePositives, metrics.FalseNegatives)
	fmt.Printf("  Precision / Recall / F1:   %.4f / %.4f / %.4f\n", metrics.Precision, metrics.Recall, metrics.F1)
	fmt.Printf("  Median Time to Alert (ms): %.2f\n", metrics.MedianTimeToAlertMs)
	fmt.Printf("  False Alerts / 1k Benign:  %.2f\n", metrics.FalseAlertsPer1kBenign)
	fmt.Printf("  Alerts Raised:             %d\n", len(alerts))
	for _, a := range alerts {
		fmt.Printf("    - [%s] %s identity=%s services=%v events=%v order_uncertain=%v\n",
			a.PathOrRule, a.AlertID, a.Identity, a.Services, a.EventIDs, a.OrderUncertain)
	}
}
