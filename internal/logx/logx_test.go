package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	l.Info("info %d", 1)
	l.Success("success")
	l.Warn("warn")
	l.Verbose("hidden")
	out := buf.String()

	for _, want := range []string{"[*] info 1", "[+] success", "[!] warn"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	if strings.Contains(out, "hidden") {
		t.Fatalf("verbose line leaked without --verbose: %q", out)
	}
}

func TestLoggerVerbose(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, true)
	l.Verbose("dns A example.com")
	if !strings.Contains(buf.String(), "[v] dns A example.com") {
		t.Fatalf("got %q", buf.String())
	}
}

func TestNilLogger(t *testing.T) {
	var l *Logger
	l.Info("no panic")
	l.Verbose("no panic")
}

type recordActivity struct {
	events []string
}

func (a *recordActivity) Pause()  { a.events = append(a.events, "pause") }
func (a *recordActivity) Resume() { a.events = append(a.events, "resume") }

func TestLoggerPausesActivity(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	a := &recordActivity{}
	l.SetActivity(a)
	l.Info("hello")

	if !strings.Contains(buf.String(), "[*] hello") {
		t.Fatalf("log output = %q", buf.String())
	}
	if len(a.events) != 2 || a.events[0] != "pause" || a.events[1] != "resume" {
		t.Fatalf("activity events = %v", a.events)
	}
}
