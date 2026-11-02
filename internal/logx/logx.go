// Package logx is a tiny thread-safe progress logger. It keeps the CLI's
// [*]/[+]/[!]/[v] prefixes consistent and centralises the --verbose filter.
package logx

import (
	"fmt"
	"io"
	"sync"
)

// Activity is an optional live display (for example a terminal spinner)
// that must be paused while a log line is written and resumed afterwards.
type Activity interface {
	Pause()
	Resume()
}

// Logger writes prefixed progress lines. A nil *Logger is safe to use.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	verbose  bool
	activity Activity
}

// New returns a logger writing to w. Verbose lines are suppressed unless
// verbose is true.
func New(w io.Writer, verbose bool) *Logger {
	return &Logger{w: w, verbose: verbose}
}

// SetActivity installs or clears a live display. It must be called before
// concurrent logging starts (for example immediately before a scan).
func (l *Logger) SetActivity(a Activity) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.activity = a
	l.mu.Unlock()
}

func (l *Logger) write(prefix, format string, args ...any) {
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.activity != nil {
		l.activity.Pause()
	}
	fmt.Fprintf(l.w, prefix+format+"\n", args...)
	if l.activity != nil {
		l.activity.Resume()
	}
}

// Info is normal progress output.
func (l *Logger) Info(format string, args ...any) { l.write("[*] ", format, args...) }

// Success marks a useful result.
func (l *Logger) Success(format string, args ...any) { l.write("[+] ", format, args...) }

// Warn marks a recoverable problem.
func (l *Logger) Warn(format string, args ...any) { l.write("[!] ", format, args...) }

// Verbose is per-query/detail output, shown only with --verbose.
func (l *Logger) Verbose(format string, args ...any) {
	if l == nil || !l.verbose {
		return
	}
	l.write("[v] ", format, args...)
}
