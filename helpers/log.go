package helpers

import (
	"fmt"
	"github.com/fatih/color"
	"time"
)

type Logger struct {
	notices []string
	warns []string
	errors []string
}

func timeLogStr() string {
	t := time.Now()
	return fmt.Sprintf("%02d:%02d:%02d.%03d",
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond() / int(time.Millisecond))
}

func (l *Logger) NewLine() {
	fmt.Printf("\n")
}

func (l *Logger) Log(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Printf("%s ▶ %s\n", timeLogStr(), line)
}

func (l *Logger) Notice(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Printf("%s ▶ %s\n", timeLogStr(), line)
	l.notices = append(l.notices, line)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Printf("%s ▶ %s\n", timeLogStr(), line)
	l.warns = append(l.warns, line)
}

func (l *Logger) Error(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	fmt.Printf("%s ▶ %s\n", timeLogStr(), line)
	l.errors = append(l.errors, line)
}

func (l Logger) PrintSummary() {
	for _, line := range l.notices {
		fmt.Printf("%s %s\n", color.WhiteString("[INFO]"), line)
	}
	for _, line := range l.warns {
		fmt.Printf("%s %s\n", color.YellowString("[WARN]"), line)
	}
	for _, line := range l.errors {
		fmt.Printf("%s %s\n", color.RedString("[ERROR]"), line)
	}

	fmt.Printf("\n")
	if len(l.warns) > 0 || len(l.errors) > 0 {
		fmt.Printf("Found multiple issues, see listing above.")
	} else {
		fmt.Printf("Nothing of importance to note!  Nice job!")
	}
}
