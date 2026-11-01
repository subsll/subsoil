package main

import "strings"

// stringList is a repeatable string flag. Values are accumulated in order and
// joined with commas, which is the format dnsx.ParseServers accepts.
type stringList struct {
	values []string
}

func (s *stringList) String() string { return strings.Join(s.values, ",") }

func (s *stringList) Set(v string) error {
	s.values = append(s.values, v)
	return nil
}
