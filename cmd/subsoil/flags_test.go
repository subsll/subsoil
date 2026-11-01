package main

import "testing"

func TestStringList(t *testing.T) {
	var l stringList
	if got := l.String(); got != "" {
		t.Fatalf("empty list String() = %q", got)
	}
	for _, v := range []string{"1.1.1.1", "8.8.8.8,9.9.9.9"} {
		if err := l.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := l.String(), "1.1.1.1,8.8.8.8,9.9.9.9"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
