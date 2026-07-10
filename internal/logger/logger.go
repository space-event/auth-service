package logger

import (
	"log/slog"
	"os"
)

var log *slog.Logger

func Init(level string) {

	var logLevel slog.Level

	switch level {
	case "info":
		logLevel = slog.LevelInfo
	case "debug":
		logLevel = slog.LevelDebug
	case "error":
		logLevel = slog.LevelError
	case "warn":
		logLevel = slog.LevelWarn
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	log = slog.New(handler)
}

func Info(msg string, args ...any) {
	log.Info(msg, args...)
}

func Debug(msg string, args ...any) {
	log.Debug(msg, args...)
}
func Error(msg string, args ...any) {
	log.Error(msg, args...)
}
func Warn(msg string, args ...any) {
	log.Warn(msg, args...)
}
