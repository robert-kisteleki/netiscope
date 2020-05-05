package util

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/fatih/color"
)

// LogLevelType defines severity of log messages
type LogLevelType int

// return levels for checks
const (
	LevelDetail  = 0
	LevelInfo    = 1
	LevelWarning = 2
	LevelError   = 3
	LevelFatal   = 4
	LevelTodo    = 5
)

// LogLevel defines what should be loggged
var LogLevel = LevelInfo // by default: info or above are reported

// Name returns the human readable name of a loglevel
func (l LogLevelType) String() string {
	var logLevelNames = map[LogLevelType]string{
		LevelDetail:  "DETAIL",
		LevelInfo:    "INFO",
		LevelWarning: "WARNING",
		LevelError:   "ERROR",
		LevelFatal:   "FATAL",
		LevelTodo:    "TODO",
	}
	return logLevelNames[l]
}

// Color returns the assigned (terminal) color of a loglevel
func (l LogLevelType) Color() color.Attribute {
	var logLevelColors = map[LogLevelType]color.Attribute{
		LevelDetail:  color.FgBlue,
		LevelInfo:    color.FgGreen,
		LevelWarning: color.FgHiYellow,
		LevelError:   color.FgRed,
		LevelFatal:   color.FgMagenta,
		LevelTodo:    color.FgCyan,
	}
	return logLevelColors[l]
}

// Finding describes one finding/observation
type Finding struct {
	Timestamp string       `json:"timestamp"`
	Check     string       `json:"check"`
	Level     LogLevelType `json:"level"`
	Mnemonic  string       `json:"mnemonic"`
	Details   interface{}  `json:"details"`
}

var findings []Finding

// Log logs one finding
func Log(check string, level LogLevelType, mnemonic string, details ...interface{}) {
	now := time.Now().Format(time.RFC3339)

	if (level == LevelFatal) || (level == LevelTodo) ||
		(level == LevelError && LogLevel <= 3) ||
		(level == LevelWarning && LogLevel <= 2) ||
		(level == LevelInfo && LogLevel <= 1) ||
		(level == LevelDetail && LogLevel == 0) {

		if ColoredOutput() {
			color.Set(level.Color())
			defer color.Unset()
		}

		fmt.Print(now)
		fmt.Printf("\t%s", check)
		fmt.Printf("\t%s", level.String())
		fmt.Printf("\t%s", mnemonic)
		if details != nil {
			encoded, _ := json.Marshal(details)
			fmt.Printf("\t%s", string(encoded))
		}
		fmt.Println()
	}

	addFinding(now, check, level, mnemonic, details)
}

// AddFinding is a shorthand to add a net Detail to the list
func addFinding(now string, check string, level LogLevelType, mnemonic string, details interface{}) {
	newFinding := Finding{
		Timestamp: now,
		Check:     check,
		Level:     level,
		Mnemonic:  mnemonic,
		Details:   details,
	}
	findings = append(findings, newFinding)
}

// DurationToHuman produces a humanised string version of a Duration
func DurationToHuman(duration time.Duration) string {
	duration = duration.Round(time.Second)
	day := duration / (time.Hour * 24)
	duration %= time.Hour * 24
	hour := duration / time.Hour
	duration %= time.Hour
	minute := duration / time.Minute
	duration %= time.Minute
	second := duration / time.Second
	switch {
	case day > 0:
		{
			return fmt.Sprintf("%dd %dh %dm %ds", day, hour, minute, second)
		}
	case hour > 0:
		{
			return fmt.Sprintf("%dh %dm %ds", hour, minute, second)
		}
	default:
		{
			return fmt.Sprintf("%dm %ds", minute, second)
		}
	}
}
