// Package logx is a tiny thread-safe progress logger. It keeps the CLI's
// [*]/[+]/[!]/[v] prefixes consistent and centralises the --verbose filter.
package logx

import (
	"fmt"
	"io"
	"sync"
)

// Logger writes prefixed progress lines. A nil *Logger is safe to use.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	verbose bool
}

// New returns a logger writing to w. Verbose lines are suppressed unless
// verbose is true.
func New(w io.Writer, verbose bool) *Logger {
	return &Logger{w: w, verbose: verbose}
}

func (l *Logger) write(prefix, format string, args ...any) {
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, prefix+format+"\n", args...)
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
