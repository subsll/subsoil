package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSpinnerPauseResumeAndStop(t *testing.T) {
	var buf bytes.Buffer
	s := newSpinner(&buf, "scanning example.com", false)
	s.interval = 5 * time.Millisecond
	s.Start()
	time.Sleep(20 * time.Millisecond)
	s.Pause()
	fmt.Fprint(&buf, "[*] log line\n")
	s.Resume()
	time.Sleep(15 * time.Millisecond)
	s.Stop()
	s.Stop()

	out := buf.String()
	if !strings.Contains(out, "scanning example.com") {
		t.Fatalf("spinner label missing: %q", out)
	}
	if !strings.Contains(out, "[*] log line") {
		t.Fatalf("log line missing: %q", out)
	}
	if !strings.Contains(out, "\r\x1b[2K") {
		t.Fatalf("spinner did not clear its line: %q", out)
	}
}

func TestFormatSpinnerElapsed(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{65 * time.Second, "1m05s"},
		{-time.Second, "0s"},
	}
	for _, c := range cases {
		if got := formatSpinnerElapsed(c.in); got != c.want {
			t.Errorf("formatSpinnerElapsed(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
