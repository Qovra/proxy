package debug

import (
	"fmt"
	"log"
	"sync/atomic"
)

var enabled atomic.Bool

// Enable turns on debug logging.
func Enable() {
	enabled.Store(true)
}

// Enabled returns whether debug logging is active.
func Enabled() bool {
	return enabled.Load()
}

// Printf logs a debug message if debug mode is enabled.
func Printf(format string, args ...any) {
	if !enabled.Load() {
		return
	}
	log.Output(2, fmt.Sprintf("[debug] "+format, args...))
}
