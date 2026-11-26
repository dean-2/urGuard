package detector

import (
	"fmt"
	"strings"
	"time"
)

// ServiceEdge represents an observed (SourceService -> TargetService) transition.
type ServiceEdge struct {
	SourceService string
	TargetService string
	EventID       string
	Timestamp     time.Time
	Outcome       string
}

// AccessGraph maintains an in-memory directed multigraph of Identity -> Source -> Target
// transitions and detects lateral movement candidates without AI/ML.
type AccessGraph struct {
	// allowedEdgesByRole defines known-good service edges per role.
	allowedEdgesByRole map[string]map[string]bool
	// flowHistory groups unexpected edges by (actor, session, correlation_id).
	flowHistory map[string][]ServiceEdge
	// baselineCounts tracks observed frequency of (actor, source->target).
	baselineCounts map[string]int
	// lastSessionByActor tracks recent (source_service, session_id, timestamp) for concurrent-node detection.
	lastSessionByActor map[string]actorSessionObs
	// WindowW is the time window for multi-hop pivot detection.
	WindowW time.Duration
	// ConcurrentWindow is the window for disjoint-node concurrent credential usage.
	ConcurrentWindow time.Duration
	// MinHopsForAlert is the minimum consecutive unexpected edges (k >= 2).
	MinHopsForAlert int
}

type actorSessionObs struct {
	SourceService string
	SessionID     string
	EventID       string
	Timestamp     time.Time
}

// NewAccessGraph initializes the lateral movement graph with default Track-4 role baselines.
func NewAccessGraph(windowW time.Duration, minHops int) *AccessGraph {
	if windowW <= 0 {
		windowW = 5 * time.Minute
	}
	if minHops < 2 {
		minHops = 2
	}

	allowed := map[string]map[string]bool{
		"viewer": {
			"portal->identity": true,
			"portal->catalog":  true,
		},
		"report-reader": {
			"portal->identity":       true,
			"portal->catalog":        true,
			"portal->reports":        true,
			"portal->reports-node-a": true,
			"portal->reports-node-b": true,
		},
		"operator": {
			"admin-console->identity": true,
			"portal->identity":        true,
			"portal->catalog":         true,
			"portal->reports":         true,
		},
		"service-reader": {
			"reports->catalog": true,
		},
	}

	return &AccessGraph{
		allowedEdgesByRole: allowed,
		flowHistory:        make(map[string][]ServiceEdge),
		baselineCounts:     make(map[string]int),
		lastSessionByActor: make(map[string]actorSessionObs),
		WindowW:            windowW,
		ConcurrentWindow:   5 * time.Second,
		MinHopsForAlert:    minHops,
	}
}

// Observe records an event edge in the graph and returns a lateral-movement Alert
// when an actor traverses >= MinHopsForAlert unexpected service edges within WindowW
// or uses the same identity concurrently from disjoint source services/sessions.
func (ag *AccessGraph) Observe(ev NormalizedEvent, wb *WatermarkBuffer) *Alert {
	if ev.SourceService == "" || ev.TargetService == "" {
		return nil
	}

	// Check concurrent disjoint-node credential usage across distinct sessions.
	if prev, ok := ag.lastSessionByActor[ev.Actor]; ok {
		dt := ev.AdjustedTimeUTC.Sub(prev.Timestamp)
		if dt < 0 {
			dt = -dt
		}
		if ev.SessionID != "" && prev.SessionID != "" &&
			ev.SessionID != prev.SessionID &&
			ev.SourceService != prev.SourceService &&
			dt <= ag.ConcurrentWindow {
			ag.lastSessionByActor[ev.Actor] = actorSessionObs{
				SourceService: ev.SourceService,
				SessionID:     ev.SessionID,
				EventID:       ev.EventID,
				Timestamp:     ev.AdjustedTimeUTC,
			}
			return &Alert{
				AlertID:         "alert-disjoint-" + ev.EventID,
				Identity:        ev.Actor,
				Classification:  ClassLateralMovementCandidate,
				PathOrRule:      "GRAPH_CONCURRENT_DISJOINT_NODE",
				Services:        []string{prev.SourceService, ev.SourceService, ev.TargetService},
				EventIDs:        []string{prev.EventID, ev.EventID},
				Explanation:     fmt.Sprintf("Actor %s used distinct sessions (%s, %s) from disjoint sources (%s, %s) within %v", ev.Actor, prev.SessionID, ev.SessionID, prev.SourceService, ev.SourceService, dt),
				ConfidenceScore: 0.90,
				DetectedAtUTC:   ev.ReceivedTimeUTC,
			}
		}
	}
	ag.lastSessionByActor[ev.Actor] = actorSessionObs{
		SourceService: ev.SourceService,
		SessionID:     ev.SessionID,
		EventID:       ev.EventID,
		Timestamp:     ev.AdjustedTimeUTC,
	}

	edgeKey := ev.SourceService + "->" + ev.TargetService
	baseKey := ev.Actor + "|" + edgeKey
	ag.baselineCounts[baseKey]++

	if ag.isExpectedEdge(ev.RoleAfter, edgeKey) {
		return nil
	}

	// Group unexpected edges by actor + session + correlation_id (flow).
	flowKey := ev.Actor + "|" + ev.SessionID + "|" + ev.CorrelationID
	edge := ServiceEdge{
		SourceService: ev.SourceService,
		TargetService: ev.TargetService,
		EventID:       ev.EventID,
		Timestamp:     ev.AdjustedTimeUTC,
		Outcome:       ev.Outcome,
	}

	history := append(ag.flowHistory[flowKey], edge)
	// Prune edges outside WindowW.
	cutoff := ev.AdjustedTimeUTC.Add(-ag.WindowW)
	var active []ServiceEdge
	for _, e := range history {
		if !e.Timestamp.Before(cutoff) {
			active = append(active, e)
		}
	}
	ag.flowHistory[flowKey] = active

	// Isolated single unexpected denial does not trigger lateral movement (e.g., evt-020).
	if len(active) < ag.MinHopsForAlert {
		return nil
	}

	services := make([]string, 0, len(active)+1)
	eventIDs := make([]string, 0, len(active))
	for i, e := range active {
		if i == 0 {
			services = append(services, e.SourceService)
		}
		services = append(services, e.TargetService)
		eventIDs = append(eventIDs, e.EventID)
	}

	pathStr := strings.Join(services, " -> ")
	return &Alert{
		AlertID:         "alert-lm-" + ev.EventID,
		Identity:        ev.Actor,
		Classification:  ClassLateralMovementCandidate,
		PathOrRule:      "GRAPH_MULTI_HOP_PIVOT",
		Services:        services,
		EventIDs:        eventIDs,
		Explanation:     fmt.Sprintf("Actor %s traversed %d unexpected service edges (%s) in flow %s/%s", ev.Actor, len(active), pathStr, ev.SessionID, ev.CorrelationID),
		ConfidenceScore: 0.92,
		DetectedAtUTC:   ev.ReceivedTimeUTC,
	}
}

func (ag *AccessGraph) isExpectedEdge(role, edgeKey string) bool {
	if roleMap, ok := ag.allowedEdgesByRole[role]; ok {
		return roleMap[edgeKey]
	}
	return false
}
