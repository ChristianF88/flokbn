package ingestor

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// BenchmarkIngestWire measures the whole ingest path for one Filebeat-sized
// batch: read the frames off a TCP connection, inflate, decode, queue,
// acknowledge, and parse in ReadBatch. The batch is serialised once up front
// so client-side cost stays out of the measurement. It uses only the public
// ingestor API, so the same file runs against older revisions for comparison.
func BenchmarkIngestWire(b *testing.B) {
	const events = 2048
	for _, compressed := range []bool{true, false} {
		name := "plain"
		if compressed {
			name = "compressed"
		}
		b.Run(name, func(b *testing.B) {
			wire := benchWindow(b, events, compressed)

			ing, err := NewTCPIngestor("127.0.0.1:0", 10*time.Second)
			if err != nil {
				b.Fatalf("NewTCPIngestor: %v", err)
			}
			defer ing.Close()
			if err := ing.Accept(); err != nil {
				b.Fatalf("Accept: %v", err)
			}
			c, err := net.Dial("tcp", ing.Addr().String())
			if err != nil {
				b.Fatalf("dial: %v", err)
			}
			defer c.Close()

			b.SetBytes(int64(len(wire)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.Write(wire); err != nil {
					b.Fatalf("write: %v", err)
				}
				var ack [6]byte
				for {
					if _, err := io.ReadFull(c, ack[:]); err != nil {
						b.Fatalf("reading ack: %v", err)
					}
					if binary.BigEndian.Uint32(ack[2:]) == events {
						break
					}
				}
				for got := 0; got < events; {
					batch, err := ing.ReadBatch()
					if err != nil {
						b.Fatalf("ReadBatch: %v", err)
					}
					if len(batch) == 0 {
						runtime.Gosched()
					}
					got += len(batch)
				}
			}
		})
	}
}

// benchWindow serialises one window of Filebeat-shaped events.
func benchWindow(b *testing.B, events int, compressed bool) []byte {
	b.Helper()
	var frames bytes.Buffer
	for i := 1; i <= events; i++ {
		line := fmt.Sprintf(`198.51.%d.%d - - [12/Mar/2024:15:04:05 -0700] "GET /api/items/%d?page=2 HTTP/1.1" 200 5123 "https://example.com/list" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"`,
			i/256, i%256, i)
		payload := fmt.Sprintf(`{"@timestamp":"2024-03-12T22:04:05.123Z","@metadata":{"beat":"filebeat","type":"_doc","version":"8.12.2"},"agent":{"ephemeral_id":"0b1e2c7a-58a4-4f6e-9a55-0d8f1d0c2f11","id":"f3a1c2d4-7b6e-4c1a-8f0d-2e9b7a6c5d43","name":"web1","type":"filebeat","version":"8.12.2"},"ecs":{"version":"8.0.0"},"host":{"name":"web1"},"input":{"type":"filestream"},"log":{"file":{"path":"/var/log/nginx/access.log"},"offset":%d},"message":%q}`,
			i*211, line)
		var hdr [10]byte
		hdr[0], hdr[1] = '2', 'J'
		binary.BigEndian.PutUint32(hdr[2:], uint32(i))
		binary.BigEndian.PutUint32(hdr[6:], uint32(len(payload)))
		frames.Write(hdr[:])
		frames.WriteString(payload)
	}

	var wire bytes.Buffer
	var win [6]byte
	win[0], win[1] = '2', 'W'
	binary.BigEndian.PutUint32(win[2:], uint32(events))
	wire.Write(win[:])
	if !compressed {
		wire.Write(frames.Bytes())
		return wire.Bytes()
	}
	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, 3)
	if err != nil {
		b.Fatalf("zlib: %v", err)
	}
	if _, err := zw.Write(frames.Bytes()); err != nil {
		b.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		b.Fatalf("zlib close: %v", err)
	}
	var chdr [6]byte
	chdr[0], chdr[1] = '2', 'C'
	binary.BigEndian.PutUint32(chdr[2:], uint32(z.Len()))
	wire.Write(chdr[:])
	wire.Write(z.Bytes())
	return wire.Bytes()
}
