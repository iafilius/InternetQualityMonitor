package monitor

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// LogLevel represents severity.
type LogLevel int32

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = map[string]LogLevel{
	"debug":   LevelDebug,
	"info":    LevelInfo,
	"warn":    LevelWarn,
	"warning": LevelWarn,
	"error":   LevelError,
}

var currentLevel int32 = int32(LevelInfo)

var baseLogger = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds)

// SetLogLevel parses and sets global log level.
func SetLogLevel(s string) {
	l, ok := levelNames[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return
	}
	atomic.StoreInt32(&currentLevel, int32(l))
}

func getLevel() LogLevel { return LogLevel(atomic.LoadInt32(&currentLevel)) }

// GetLogLevel returns current global log level (exported for conditional debug logic outside package).
func GetLogLevel() LogLevel { return getLevel() }

func logf(l LogLevel, format string, args ...interface{}) {
	if getLevel() > l {
		return
	}
	prefix := "INFO"
	switch l {
	case LevelDebug:
		prefix = "DEBUG"
	case LevelWarn:
		prefix = "WARN"
	case LevelError:
		prefix = "ERROR"
	}
	// Only format when there are args; otherwise treat the input as a plain message to avoid
	// fmt parsing literal % characters in already formatted strings (which would yield %!x(MISSING)).
	if len(args) == 0 {
		baseLogger.Printf("[%s] %s", prefix, format)
		return
	}
	baseLogger.Printf("[%s] %s", prefix, fmt.Sprintf(format, args...))
}

// Public helpers
func Debugf(format string, a ...interface{}) { logf(LevelDebug, format, a...) }
func Infof(format string, a ...interface{})  { logf(LevelInfo, format, a...) }
func Warnf(format string, a ...interface{})  { logf(LevelWarn, format, a...) }
func Errorf(format string, a ...interface{}) { logf(LevelError, format, a...) }

// Timing helper for phases.
func TimeTrack(start time.Time, label string) {
	dur := time.Since(start)
	Debugf("%s took %s", label, dur)
}
