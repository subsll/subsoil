package main

import "testing"

func TestEmailAnalysisRejectsPassiveCLI(t *testing.T) {
	if code := cmdScan([]string{"example.test", "--passive", "--email-analysis", "--sources", "none"}); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
