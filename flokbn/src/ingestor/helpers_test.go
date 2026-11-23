package ingestor

import (
	"encoding/json"
	"errors"
)

// The ingestor used to queue go-lumber batches of generically decoded JSON
// events (map[string]interface{}) and parse those. It now decodes only the
// "message" field on the wire side and parses plain lines. The helpers below
// let the existing map-based test corpus keep driving the same code:
// parseEvent/parseEventSafe pull the message out of a decoded event exactly
// as the old parser's first step did, and makeBatch pushes each event through
// the real wire decoder (eventBatch.add) as JSON.

func parseEvent(evt map[string]interface{}, out *Request) (int, error) {
	msg, ok := evt["message"].(string)
	if !ok {
		return 0, errors.New("missing message field")
	}
	return parseLine(msg, out)
}

func parseEventSafe(evt map[string]interface{}, out *Request) (int, error) {
	msg, ok := evt["message"].(string)
	if !ok {
		return 0, errors.New("missing message field")
	}
	return parseLineSafe(msg, out)
}

// makeBatch builds a queued batch from events as a Lumberjack client would
// send them: each one JSON-encoded and decoded by the wire decoder.
func makeBatch(events ...interface{}) *eventBatch {
	b := &eventBatch{}
	for _, evt := range events {
		payload, err := json.Marshal(evt)
		if err != nil {
			panic(err)
		}
		b.add(payload)
	}
	// Nothing was reserved from the queue budget for a hand-made batch, so
	// it must not give anything back when ReadBatch consumes it.
	b.cost = 0
	return b
}

// newQueueIngestor returns an ingestor with only its batch queue set up, for
// tests that feed ReadBatch directly without a network listener.
func newQueueIngestor(capacity int) *TCPIngestor {
	limits := DefaultLimits()
	return &TCPIngestor{
		events: make(chan *eventBatch, capacity),
		budget: newByteBudget(limits.MaxQueuedBytes),
		limits: limits,
	}
}
