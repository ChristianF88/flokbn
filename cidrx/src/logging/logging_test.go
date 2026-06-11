package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"", slog.LevelInfo, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"debug", slog.LevelDebug, false},
		{"Debug", slog.LevelDebug, false},
		{"warn", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"ERROR", slog.LevelError, false},
		{"verbose", 0, true},
		{"warning2", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseLevel(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseLevel(%q) err = nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q) err = %v, want nil", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		level, format string
		wantErr       bool
	}{
		{"", "", false},
		{"info", "text", false},
		{"debug", "json", false},
		{"WARN", "TEXT", false},
		{"error", "JSON", false},
		{"verbose", "text", true},
		{"info", "xml", true},
		{"nope", "nope", true},
	}
	for _, tc := range cases {
		err := Validate(tc.level, tc.format)
		if (err != nil) != tc.wantErr {
			t.Errorf("Validate(%q, %q) err = %v, wantErr %v", tc.level, tc.format, err, tc.wantErr)
		}
	}
}

func TestNew_LevelFiltering(t *testing.T) {
	cases := []struct {
		level      string
		wantDebug  bool
		wantInfo   bool
		wantWarn   bool
		wantErrLvl bool
	}{
		{"debug", true, true, true, true},
		{"", false, true, true, true}, // default = info
		{"info", false, true, true, true},
		{"warn", false, false, true, true},
		{"error", false, false, false, true},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		logger, err := New(&buf, tc.level, "text")
		if err != nil {
			t.Fatalf("New(level=%q): %v", tc.level, err)
		}
		logger.Debug("dbg-msg")
		logger.Info("info-msg")
		logger.Warn("warn-msg")
		logger.Error("err-msg")
		out := buf.String()
		checks := []struct {
			msg  string
			want bool
		}{
			{"dbg-msg", tc.wantDebug},
			{"info-msg", tc.wantInfo},
			{"warn-msg", tc.wantWarn},
			{"err-msg", tc.wantErrLvl},
		}
		for _, c := range checks {
			if got := strings.Contains(out, c.msg); got != c.want {
				t.Errorf("level=%q: output contains %q = %v, want %v\noutput: %s", tc.level, c.msg, got, c.want, out)
			}
		}
	}
}

func TestNew_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(&buf, "info", "text")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("hello", "key", "value")
	out := buf.String()
	if !strings.Contains(out, "msg=hello") || !strings.Contains(out, "key=value") {
		t.Errorf("text output missing msg/attr: %s", out)
	}
	if !strings.Contains(out, "time=") {
		t.Errorf("text output missing timestamp: %s", out)
	}
}

func TestNew_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(&buf, "info", "json")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("hello", "key", "value")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("json output did not decode: %v\noutput: %s", err, buf.String())
	}
	if rec["msg"] != "hello" || rec["key"] != "value" || rec["level"] != "INFO" {
		t.Errorf("json record = %v, want msg=hello key=value level=INFO", rec)
	}
	if _, ok := rec["time"]; !ok {
		t.Errorf("json record missing time: %v", rec)
	}
}

func TestNew_BadValues(t *testing.T) {
	var buf bytes.Buffer
	if _, err := New(&buf, "verbose", "text"); err == nil {
		t.Error("New with bad level: err = nil, want error")
	}
	if _, err := New(&buf, "info", "xml"); err == nil {
		t.Error("New with bad format: err = nil, want error")
	}
}

func TestSetup(t *testing.T) {
	prev := slog.Default()
	defer slog.SetDefault(prev)

	if err := Setup("badlevel", "text"); err == nil {
		t.Error("Setup with bad level: err = nil, want error")
	}
	if err := Setup("debug", "json"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Setup(debug) default logger does not enable debug")
	}
}
