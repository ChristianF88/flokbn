package ingestor

import (
	"encoding/json"
	"errors"
)

// The ingestor used to queue go-lumber batches of generically decoded JSON
// events (map[string]interface{}) and parse those with a hardcoded parser. It
// now decodes only the "message" field on the wire side and parses plain lines
// with a compiled log format. The helpers below let the existing test corpus
// keep driving the same code: parseLine parses one line exactly as ReadBatch
// does, parseEvent/parseEventSafe pull the message out of a decoded event as
// the old parser's first step did, and makeBatch pushes each event through the
// real wire decoder (eventBatch.add) as JSON.

// lineIngestor parses the lines handed to parseLine. It has the default live
// log format, like every ingestor built without Options.LogFormat.
var lineIngestor = newQueueIngestor(0)

// parseLine parses one line the way ReadBatch does and also returns how many
// malformed status/bytes fields the line added to the ingestor's counter. The
// count is a before/after difference, so tests calling this must not run in
// parallel.
func parseLine(msg string, out *Request) (malformed int, err error) {
	before := lineIngestor.Stats().MalformedFieldsTotal
	err = lineIngestor.parseLine(msg, out)
	return int(lineIngestor.Stats().MalformedFieldsTotal - before), err
}

func parseEvent(evt map[string]interface{}, out *Request) (int, error) {
	msg, ok := evt["message"].(string)
	if !ok {
		return 0, errors.New("missing message field")
	}
	return parseLine(msg, out)
}

// parseEventSafe is parseEvent: the recover guard it used to add is part of
// TCPIngestor.parseLine now.
func parseEventSafe(evt map[string]interface{}, out *Request) (int, error) {
	return parseEvent(evt, out)
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

// newQueueIngestor returns an ingestor with only its batch queue and line
// parser set up, for tests that feed ReadBatch directly without a network
// listener. logFormat is optional; without it the default live format is used.
func newQueueIngestor(capacity int, logFormat ...string) *TCPIngestor {
	format := ""
	if len(logFormat) > 0 {
		format = logFormat[0]
	}
	parser, err := newLineParser(format)
	if err != nil {
		panic(err)
	}
	limits := DefaultLimits()
	return &TCPIngestor{
		parser: parser,
		events: make(chan *eventBatch, capacity),
		budget: newByteBudget(limits.MaxQueuedBytes),
		limits: limits,
	}
}
