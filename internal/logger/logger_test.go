package logger

import (
	"os"
	"testing"
)

func TestInit(t *testing.T) {
	// Test with DEBUG environment variable not set
	os.Unsetenv("DEBUG")
	Init()

	if Log == nil {
		t.Error("Expected logger to be initialized, got nil")
	}

	// Test with DEBUG environment variable set
	os.Setenv("DEBUG", "1")
	Init()

	if Log == nil {
		t.Error("Expected logger to be initialized with DEBUG mode, got nil")
	}

	// Clean up
	os.Unsetenv("DEBUG")
}
