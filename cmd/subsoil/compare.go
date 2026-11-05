package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/subsll/subsoil/internal/evidence"
)

type compareOutput struct {
	File       string               `json:"file,omitempty"`
	Size       int64                `json:"size,omitempty"`
	SHA256     string               `json:"sha256"`
	Case       string               `json:"case"`
	RootSHA256 string               `json:"root_sha256,omitempty"`
	Records    int                  `json:"records"`
	ChainOK    bool                 `json:"chain_ok"`
	Sidecar    string               `json:"sidecar,omitempty"`
	Captured   bool                 `json:"captured"`
	Matches    []evidence.HashMatch `json:"matches"`
}

func cmdCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		casePath string
		digest   string
		jsonOut  bool
	)
	fs.StringVar(&casePath, "case", "", "case directory or evidence.jsonl")
	fs.StringVar(&casePath, "evidence", "", "alias for --case")
	fs.StringVar(&digest, "hash", "", "compare this SHA-256 instead of hashing a file")
	fs.BoolVar(&jsonOut, "json", false, "JSON output")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: subsoil compare <file> --case <case-dir|evidence.jsonl> [--json]")
		fmt.Fprintln(os.Stderr, "       subsoil compare --hash <sha256> --case <case-dir|evidence.jsonl> [--json]")
	}

	var positional string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if casePath == "" {
		fs.Usage()
		return 2
	}
	if positional != "" && fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "subsoil: compare takes one file")
		return 2
	}

	file := positional
	if file == "" && fs.NArg() == 1 {
		file = fs.Arg(0)
	}
	if digest != "" {
		if file != "" || fs.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "subsoil: use either a file or --hash, not both")
			return 2
		}
	} else if file == "" {
		fs.Usage()
		return 2
	}

	var size int64
	if digest == "" {
		sum, n, err := evidence.FileSHA256(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
			return 2
		}
		digest = sum
		size = n
		if abs, err := filepath.Abs(file); err == nil {
			file = abs
		}
	} else {
		var err error
		digest, err = normalizeDigest(digest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
			return 2
		}
	}

	casePath, err := resolveCase(casePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
		return 2
	}
	verify, err := evidence.VerifyFile(casePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
		return 2
	}
	if !verify.OK {
		fmt.Fprintln(os.Stderr, "case chain BROKEN — refusing to compare")
		for _, e := range verify.Errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		return 2
	}

	sidecarOK, sidecarMsg := checkCaseSidecar(casePath, verify.FileSHA256)
	if !sidecarOK {
		fmt.Fprintf(os.Stderr, "subsoil: case sidecar MISMATCH: %s\n", sidecarMsg)
		return 2
	}

	matches, err := evidence.FindHashMatches(casePath, digest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
		return 2
	}
	if matches == nil {
		matches = []evidence.HashMatch{}
	}
	captured := len(matches) > 0

	if jsonOut {
		out := compareOutput{
			File:       file,
			Size:       size,
			SHA256:     digest,
			Case:       casePath,
			RootSHA256: verify.RootSHA256,
			Records:    verify.Records,
			ChainOK:    true,
			Sidecar:    sidecarMsg,
			Captured:   captured,
			Matches:    matches,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
			return 2
		}
	} else {
		fmt.Printf("case        %s\n", casePath)
		fmt.Printf("records     %d\n", verify.Records)
		fmt.Printf("chain       OK\n")
		if sidecarMsg != "" {
			fmt.Printf("sidecar     %s\n", sidecarMsg)
		}
		if file != "" {
			fmt.Printf("file        %s\n", file)
			fmt.Printf("size        %d\n", size)
		}
		fmt.Printf("sha256      %s\n", digest)
		if captured {
			fmt.Println("result      ALREADY CAPTURED")
		} else {
			fmt.Println("result      NEW EVIDENCE")
		}
		fmt.Printf("matches     %d\n", len(matches))
		limit := len(matches)
		if limit > 50 {
			limit = 50
		}
		for _, m := range matches[:limit] {
			fmt.Printf("  seq %-4d type=%-10s target=%s source=%s field=%s\n",
				m.Seq, m.Type, m.Target, m.Source, m.Field)
		}
		if len(matches) > limit {
			fmt.Printf("  ... %d more\n", len(matches)-limit)
		}
	}

	if captured {
		return 0
	}
	return 1
}

func normalizeDigest(s string) (string, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:")
	if len(s) != 64 {
		return "", fmt.Errorf("invalid SHA-256 digest: expected 64 hex characters")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("invalid SHA-256 digest: %v", err)
	}
	return s, nil
}

func resolveCase(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		path = filepath.Join(path, "evidence.jsonl")
		st, err = os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("%s does not contain evidence.jsonl: %w", filepath.Dir(path), err)
		}
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not an evidence file", path)
	}
	return path, nil
}

func checkCaseSidecar(casePath, fileHash string) (bool, string) {
	b, err := os.ReadFile(casePath + ".sha256")
	if err != nil {
		return true, ""
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return false, "empty sidecar"
	}
	if strings.EqualFold(fields[0], fileHash) {
		return true, "matches " + filepath.Base(casePath+".sha256")
	}
	return false, fmt.Sprintf("file says %s", fields[0])
}
