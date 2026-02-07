package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Level represents log level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	defaultLogger *slog.Logger
	currentLevel  Level
)

// ParseLevel parses a level string.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, nil
	}
}

// Init initializes the logger with JSON handler and level.
func Init(level Level, w io.Writer) {
	currentLevel = level
	if w == nil {
		w = os.Stdout
	}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	defaultLogger = slog.New(slog.NewJSONHandler(w, opts))
}

// Enabled returns whether level is enabled.
func Enabled(l Level) bool {
	return l >= currentLevel
}

func slogLevel(l Level) slog.Level {
	switch l {
	case LevelDebug:
		return slog.LevelDebug
	case LevelInfo:
		return slog.LevelInfo
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Log emits a structured log with level and key-value pairs.
func Log(level Level, msg string, args ...any) {
	if !Enabled(level) {
		return
	}
	defaultLogger.Log(context.TODO(), slogLevel(level), msg, args...)
}

// Debug logs at debug level.
func Debug(msg string, args ...any) {
	Log(LevelDebug, msg, args...)
}

// Info logs at info level.
func Info(msg string, args ...any) {
	Log(LevelInfo, msg, args...)
}

// Warn logs at warn level.
func Warn(msg string, args ...any) {
	Log(LevelWarn, msg, args...)
}

// Error logs at error level.
func Error(msg string, args ...any) {
	Log(LevelError, msg, args...)
}

// With returns a logger with the given attributes.
func With(args ...any) *slog.Logger {
	return defaultLogger.With(args...)
}
