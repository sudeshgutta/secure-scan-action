package logger

import (
	"log/slog"
	"os"
)

var Log *slog.Logger

func Init() {
	lvl := slog.LevelInfo
	if os.Getenv("DEBUG") == "1" {
		lvl = slog.LevelDebug
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	Log = slog.New(handler)
}
