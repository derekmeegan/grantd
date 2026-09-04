package main

import (
	"io"
	"log/slog"
)

// discardLogger keeps test output to the assertions.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
