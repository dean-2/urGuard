package detector

import (
	"container/heap"
	"time"
)

// eventMinHeap orders NormalizedEvent items by AdjustedTimeUTC (tie-broken by ReceiptSeq).
type eventMinHeap []NormalizedEvent

func (h eventMinHeap) Len() int { return len(h) }
func (h eventMinHeap) Less(i, j int) bool {
	if h[i].AdjustedTimeUTC.Equal(h[j].AdjustedTimeUTC) {
		return h[i].ReceiptSeq < h[j].ReceiptSeq
	}
	return h[i].AdjustedTimeUTC.Before(h[j].AdjustedTimeUTC)
}
func (h eventMinHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *eventMinHeap) Push(x any)        { *h = append(*h, x.(NormalizedEvent)) }
func (h *eventMinHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// WatermarkBuffer buffers out-of-order events in a min-heap up to MaxClockSkew
// before emitting them in estimated causal order.
type WatermarkBuffer struct {
	MaxClockSkew time.Duration
	watermark    time.Time
	hasWatermark bool
	heap         eventMinHeap
	recent       []NormalizedEvent // window for detecting ambiguous 2*skew pairs
}

// NewWatermarkBuffer creates a bounded out-of-orderness buffer (default ±30s).
func NewWatermarkBuffer(maxSkew time.Duration) *WatermarkBuffer {
	if maxSkew <= 0 {
		maxSkew = 30 * time.Second
	}
	return &WatermarkBuffer{
		MaxClockSkew: maxSkew,
	}
}

// Push ingests an event, advances the watermark, marks late arrivals, and returns
// any events ready to be finalized (AdjustedTimeUTC <= watermark - MaxClockSkew).
func (wb *WatermarkBuffer) Push(ev NormalizedEvent) []NormalizedEvent {
	if !wb.hasWatermark || ev.AdjustedTimeUTC.After(wb.watermark) {
		wb.watermark = ev.AdjustedTimeUTC
		wb.hasWatermark = true
	}

	cutoff := wb.watermark.Add(-wb.MaxClockSkew)
	if ev.AdjustedTimeUTC.Before(cutoff) {
		ev.LateArrival = true
		// Process late arrivals immediately with LateArrival=true rather than dropping them.
		return []NormalizedEvent{ev}
	}

	heap.Push(&wb.heap, ev)
	return wb.popBefore(cutoff)
}

// Flush drains all remaining buffered events in causal order (used at end-of-stream/batch).
func (wb *WatermarkBuffer) Flush() []NormalizedEvent {
	out := make([]NormalizedEvent, 0, wb.heap.Len())
	for wb.heap.Len() > 0 {
		out = append(out, heap.Pop(&wb.heap).(NormalizedEvent))
	}
	return out
}

func (wb *WatermarkBuffer) popBefore(cutoff time.Time) []NormalizedEvent {
	var ready []NormalizedEvent
	for wb.heap.Len() > 0 {
		top := wb.heap[0]
		if top.AdjustedTimeUTC.After(cutoff) {
			break
		}
		ready = append(ready, heap.Pop(&wb.heap).(NormalizedEvent))
	}
	return ready
}

// DetectOrderUncertainty checks whether any two events in the slice fall within
// 2 * MaxClockSkew of each other (for the same actor or session), where causal ordering
// cannot be guaranteed across unsynchronized clocks.
func (wb *WatermarkBuffer) DetectOrderUncertainty(events []NormalizedEvent) (bool, []OrderAlternative) {
	threshold := 2 * wb.MaxClockSkew
	var alts []OrderAlternative

	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			a, b := events[i], events[j]
			if a.Actor != b.Actor && (a.SessionID == "" || a.SessionID != b.SessionID) {
				continue
			}
			delta := b.AdjustedTimeUTC.Sub(a.AdjustedTimeUTC)
			if delta < 0 {
				delta = -delta
			}
			if delta < threshold {
				alts = append(alts, OrderAlternative{
					FirstEventID:  a.EventID,
					SecondEventID: b.EventID,
					DeltaMs:       delta.Milliseconds(),
				})
			}
		}
	}
	return len(alts) > 0, alts
}
