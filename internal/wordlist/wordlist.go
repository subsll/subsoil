// Package wordlist provides the embedded brute-force dictionaries and loader
// for user-supplied lists.
package wordlist

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// The dictionaries are the SecLists "subdomains-top1million" lists (MIT),
// normalised to lowercase, valid DNS labels and de-duplicated.
//
//go:embed subs5000.txt.gz
var subs5000 string

//go:embed subs20000.txt.gz
var subs20000 string

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var (
	once  sync.Once
	small []string
	large []string
	err   error
)

func load() {
	small, err = decompress(subs5000)
	if err != nil {
		return
	}
	large, err = decompress(subs20000)
}

func decompress(blob string) ([]string, error) {
	zr, err := gzip.NewReader(strings.NewReader(blob))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	return parse(bytes.NewReader(raw)), nil
}

// Load returns the embedded dictionary. extended selects the 20k list.
func Load(extended bool) ([]string, error) {
	once.Do(load)
	if err != nil {
		return nil, err
	}
	if extended {
		return append([]string(nil), large...), nil
	}
	return append([]string(nil), small...), nil
}

// LoadFile reads a user-supplied wordlist, normalising and validating entries.
// The file may be gzip-compressed regardless of its extension.
func LoadFile(path string) ([]string, error) {
	words, err := loadOne(path)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist %s contains no valid DNS labels", path)
	}
	return words, nil
}

// Result is the merged content of one or more wordlist locations.
type Result struct {
	Words   []string
	Sources []string
}

// LoadPaths loads wordlist files and/or directories, de-duplicating labels
// across sources while preserving first-seen order. A path of "-" reads stdin.
// Directories are non-recursive and load known wordlist extensions only.
func LoadPaths(paths []string) (Result, error) {
	var res Result
	stdinUsed := false
	seen := make(map[string]struct{}, 4096)
	sourceSeen := make(map[string]struct{})
	addSource := func(src string) {
		if _, ok := sourceSeen[src]; ok {
			return
		}
		sourceSeen[src] = struct{}{}
		res.Sources = append(res.Sources, src)
	}
	add := func(words []string) {
		for _, w := range words {
			if _, ok := seen[w]; ok {
				continue
			}
			seen[w] = struct{}{}
			res.Words = append(res.Words, w)
		}
	}

	for _, raw := range paths {
		path := expandHome(strings.TrimSpace(raw))
		if path == "" {
			continue
		}
		if path == "-" {
			if stdinUsed {
				continue
			}
			stdinUsed = true
			words := parse(os.Stdin)
			if len(words) == 0 {
				return res, errors.New("stdin contains no valid DNS labels")
			}
			add(words)
			addSource("-")
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			return res, fmt.Errorf("wordlist %s: %w", path, err)
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return res, fmt.Errorf("wordlist directory %s: %w", path, err)
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			loaded := 0
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || strings.HasPrefix(name, ".") || !isListName(name) {
					continue
				}
				sub := filepath.Join(path, name)
				subInfo, err := os.Stat(sub)
				if err != nil || !subInfo.Mode().IsRegular() {
					continue
				}
				words, err := loadOne(sub)
				if err != nil {
					return res, err
				}
				if len(words) == 0 {
					continue
				}
				add(words)
				addSource(sub)
				loaded++
			}
			if loaded == 0 {
				return res, fmt.Errorf("wordlist directory %s contains no .txt/.lst/.list/.wordlist/.dict/.words/.gz files", path)
			}
			continue
		}

		words, err := loadOne(path)
		if err != nil {
			return res, err
		}
		if len(words) == 0 {
			return res, fmt.Errorf("wordlist %s contains no valid DNS labels", path)
		}
		add(words)
		addSource(path)
	}

	if len(res.Words) == 0 {
		return res, errors.New("no valid DNS labels found in the supplied wordlists")
	}
	return res, nil
}

func loadOne(path string) ([]string, error) {
	if path == "-" {
		return parse(os.Stdin), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("wordlist %s: %w", path, err)
	}
	defer f.Close()

	br := bufio.NewReader(f)
	if magic, err := br.Peek(2); err == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("wordlist %s: %w", path, err)
		}
		defer zr.Close()
		return parse(zr), nil
	}
	return parse(br), nil
}

func isListName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt", ".lst", ".list", ".wordlist", ".dict", ".gz", ".words":
		return true
	}
	return false
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func parse(r io.Reader) []string {
	seen := make(map[string]struct{}, 4096)
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow "label.example.com" style lists by taking the first label.
		if i := strings.IndexByte(line, '.'); i > 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if !labelRe.MatchString(line) {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}

// ValidLabel reports whether s is a valid single DNS label.
func ValidLabel(s string) bool { return labelRe.MatchString(s) }

// Normalize sorts and de-duplicates a slice of labels.
func Normalize(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if !labelRe.MatchString(v) {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
