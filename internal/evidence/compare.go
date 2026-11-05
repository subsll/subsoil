package evidence

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// HashMatch identifies one place in a case's evidence where a SHA-256 digest
// appears. Field is a JSON path such as "data.body_sha256" or "hash".
type HashMatch struct {
	Seq    int    `json:"seq"`
	Type   string `json:"type"`
	Target string `json:"target"`
	Source string `json:"source"`
	Field  string `json:"field"`
}

// FindHashMatches searches a JSONL evidence log for digest. Callers should
// verify the chain with VerifyFile before trusting the result.
func FindHashMatches(path, digest string) ([]HashMatch, error) {
	target := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(digest)), "sha256:")
	if !isSHA256(target) {
		return nil, fmt.Errorf("invalid SHA-256 digest %q", digest)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []HashMatch
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("parse evidence record: %w", err)
		}

		add := func(field, value string) {
			if value != "" && strings.EqualFold(value, target) {
				matches = append(matches, HashMatch{
					Seq:    rec.Seq,
					Type:   rec.Type,
					Target: rec.Target,
					Source: rec.Source,
					Field:  field,
				})
			}
		}
		add("hash", rec.Hash)

		if len(rec.Data) > 0 {
			var data any
			if err := json.Unmarshal(rec.Data, &data); err != nil {
				return nil, fmt.Errorf("parse evidence data at seq %d: %w", rec.Seq, err)
			}
			walkHashFields(data, "data", add)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return matches, nil
}

func walkHashFields(v any, path string, add func(field, value string)) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			next := key
			if path != "" {
				next = path + "." + key
			}
			walkHashFields(x[key], next, add)
		}
	case []any:
		for i, item := range x {
			walkHashFields(item, fmt.Sprintf("%s[%d]", path, i), add)
		}
	case string:
		if isSHA256(x) {
			add(path, x)
		}
	}
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
