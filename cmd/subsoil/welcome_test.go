package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/subsll/subsoil/internal/model"
)

func TestWelcomePlain(t *testing.T) {
	var buf bytes.Buffer
	printWelcome(&buf, false)
	out := buf.String()

	for _, want := range []string{
		"██████",
		"Subsoil",
		"low-observable DNS reconnaissance",
		"v" + model.Version,
		"scan <domain>",
		"verify <evidence>",
		"subsoil verify <scan-dir>/evidence.jsonl",
		"--dns-servers <list>",
		"-v, --verbose",
		"authorised",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("welcome screen is missing %q", want)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("plain welcome screen contains ANSI escapes")
	}
	for i, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > 80 {
			t.Fatalf("line %d is %d columns wide", i+1, n)
		}
	}
}

func TestWelcomeColor(t *testing.T) {
	var buf bytes.Buffer
	printWelcome(&buf, true)
	out := buf.String()
	if !strings.Contains(out, "\x1b[36m") {
		t.Fatal("coloured welcome screen has no cyan wordmark")
	}
	if !strings.Contains(out, "\x1b[0m") {
		t.Fatal("coloured welcome screen never resets colour")
	}
}

func TestPadRight(t *testing.T) {
	if got := padRight("abc", 6); got != "abc   " {
		t.Fatalf("padRight = %q", got)
	}
	if got := padRight("abcdef", 3); got != "abcdef" {
		t.Fatalf("padRight should not truncate, got %q", got)
	}
}
