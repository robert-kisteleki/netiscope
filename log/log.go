package log

import (
	"fmt"
	"time"
)

// parse log level as a string and set log level accordingly
func SetLogLevel(level string, setverbose bool) {
	switch level {
	case "detail":
		LogLevel = LevelDetail
	case "info":
		LogLevel = LevelInfo
	case "warning":
		LogLevel = LevelWarning
	case "error":
		LogLevel = LevelError
	}
}

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
	LevelAdmin   = 6
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
		LevelAdmin:   "ADMIN",
	}
	return logLevelNames[l]
}

// ResultItem describes one finding/observation
type ResultItem struct {
	Check     string       `json:"check"`
	Level     LogLevelType `json:"level"`
	Mnemonic  string       `json:"mnemonic"`
	Details   string       `json:"details"`
	Timestamp string       `json:"timestamp"`
}

type Check struct {
	Name      string
	Collector []ResultItem
	Tracker   chan string
}

var AllResults chan ResultItem

// NewFinding logs one finding
func NewFinding(check string, level LogLevelType, mnemonic string, details string) ResultItem {
	now := time.Now().Format(time.RFC3339)
	return ResultItem{
		Timestamp: now,
		Check:     check,
		Level:     level,
		Mnemonic:  mnemonic,
		Details:   details,
	}
}

func NewResultItem(check *Check, level LogLevelType, mnemonic string, details string) {
	finding := NewFinding(check.Name, level, mnemonic, details)
	check.Collector = append(check.Collector, finding)
	AllResults <- finding
}

func PrintResultItem(finding ResultItem) {
	level := finding.Level
	if (level == LevelFatal) || (level == LevelTodo) ||
		(level == LevelAdmin) ||
		(level == LevelError && LogLevel <= 3) ||
		(level == LevelWarning && LogLevel <= 2) ||
		(level == LevelInfo && LogLevel <= 1) ||
		(level == LevelDetail && LogLevel == 0) {

		fmt.Print(finding.Timestamp)
		fmt.Printf("\t%s", level.String())
		fmt.Printf("\t%s", finding.Check)
		fmt.Printf("\t%s", finding.Mnemonic)
		if finding.Details != "" {
			fmt.Printf("\t%s", finding.Details)
		}
		fmt.Println()
	}
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
		return fmt.Sprintf("%dd %dh %dm %ds", day, hour, minute, second)
	case hour > 0:
		return fmt.Sprintf("%dh %dm %ds", hour, minute, second)
	default:
		return fmt.Sprintf("%dm %ds", minute, second)
	}
}

func Track(check *Check) {
	check.Tracker <- check.Name
}
