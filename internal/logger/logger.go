package logger

import (
	"log/slog"
	"os"
)

var Log *slog.Logger

func Init() {
	level := slog.LevelInfo
	if os.Getenv("DEBUG") == "1" {
		level = slog.LevelDebug
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	Log = slog.New(handler)
}
