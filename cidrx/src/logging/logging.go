// Package logging provides cidrx's general logging facility on top of the
// stdlib log/slog. It owns the canonical validation of the level and format
// enums so config validation and logger construction can never disagree.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// ParseLevel maps a config/flag level string to a slog.Level. Matching is
// case-insensitive; the empty string defaults to info.
func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("invalid log level %q (want debug, info, warn or error)", level)
}

// Validate reports whether level and format are acceptable values, using the
// exact same rules New applies. Empty strings are valid (defaults).
func Validate(level, format string) error {
	if _, err := ParseLevel(level); err != nil {
		return err
	}
	switch strings.ToLower(format) {
	case "", "text", "json":
		return nil
	}
	return fmt.Errorf("invalid log format %q (want text or json)", format)
}

// New returns a leveled slog.Logger writing to w. format selects the handler:
// "text" (default for empty) or "json". level defaults to info for empty.
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(format) {
	case "", "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("invalid log format %q (want text or json)", format)
}

// Setup installs the process-wide default logger (slog.SetDefault) writing to
// os.Stderr with the given level and format.
func Setup(level, format string) error {
	logger, err := New(os.Stderr, level, format)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	return nil
}
