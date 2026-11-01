// Package evidence implements an append-only, hash-chained evidence log.
//
// Each record hashes a canonical JSON payload that includes the previous
// record's hash. Changing, removing or re-ordering any record breaks the chain,
// which is what makes the log usable as proof of what a scan observed.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Record is one line of the evidence log.
type Record struct {
	Seq      int             `json:"seq"`
	Time     string          `json:"time"`
	Type     string          `json:"type"`
	Target   string          `json:"target"`
	Source   string          `json:"source"`
	PrevHash string          `json:"prev_hash,omitempty"`
	Data     json.RawMessage `json:"data"`
	Hash     string          `json:"hash"`
}

// Info describes a closed log.
type Info struct {
	File       string `json:"file"`
	Records    int    `json:"records"`
	RootSHA256 string `json:"root_sha256"`
	FileSHA256 string `json:"file_sha256"`
	ChainOK    bool   `json:"chain_ok"`
}

type payload struct {
	Seq      int             `json:"seq"`
	Time     string          `json:"time"`
	Type     string          `json:"type"`
	Target   string          `json:"target"`
	Source   string          `json:"source"`
	PrevHash string          `json:"prev_hash,omitempty"`
	Data     json.RawMessage `json:"data"`
}

// Recorder appends hash-chained records to a file.
type Recorder struct {
	mu     chan struct{} // used as a mutex so Add can be called from many goroutines
	f      *os.File
	bw     *bufio.Writer
	fh     hash.Hash
	path   string
	seq    int
	prev   string
	closed bool
}

// NewRecorder creates/truncates path and prepares it for appending.
func NewRecorder(path string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	r := &Recorder{
		mu:   make(chan struct{}, 1),
		f:    f,
		bw:   bufio.NewWriterSize(f, 64*1024),
		fh:   sha256.New(),
		path: path,
	}
	r.mu <- struct{}{}
	return r, nil
}

// Path returns the log path.
func (r *Recorder) Path() string { return r.path }

// Add appends a finding and returns the stored record (including its hash).
func (r *Recorder) Add(typ, target, source string, data any) (Record, error) {
	<-r.mu
	defer func() { r.mu <- struct{}{} }()

	if r.closed {
		return Record{}, errors.New("evidence: recorder is closed")
	}

	dataJSON, err := marshalJSON(data)
	if err != nil {
		return Record{}, fmt.Errorf("evidence: marshal data: %w", err)
	}

	rec := Record{
		Seq:      r.seq + 1,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Type:     typ,
		Target:   target,
		Source:   source,
		PrevHash: r.prev,
		Data:     dataJSON,
	}

	canon, err := canonical(rec)
	if err != nil {
		return Record{}, err
	}
	sum := sha256.Sum256(canon)
	rec.Hash = hex.EncodeToString(sum[:])

	line, err := marshalJSON(rec)
	if err != nil {
		return Record{}, fmt.Errorf("evidence: marshal record: %w", err)
	}
	line = append(line, '\n')
	if _, err := r.bw.Write(line); err != nil {
		return Record{}, err
	}
	if _, err := r.fh.Write(line); err != nil {
		return Record{}, err
	}

	r.seq = rec.Seq
	r.prev = rec.Hash
	return rec, nil
}

// Close flushes the log and returns its summary. It is safe to call twice.
func (r *Recorder) Close() (Info, error) {
	<-r.mu
	defer func() { r.mu <- struct{}{} }()

	info := Info{
		File:       r.path,
		Records:    r.seq,
		RootSHA256: r.prev,
		ChainOK:    true,
	}
	if r.closed {
		info.FileSHA256 = hex.EncodeToString(r.fh.Sum(nil))
		return info, nil
	}

	if err := r.bw.Flush(); err != nil {
		r.closed = true
		_ = r.f.Close()
		return info, err
	}
	if err := r.f.Sync(); err != nil {
		r.closed = true
		_ = r.f.Close()
		return info, err
	}
	if err := r.f.Close(); err != nil {
		r.closed = true
		return info, err
	}
	r.closed = true
	info.FileSHA256 = hex.EncodeToString(r.fh.Sum(nil))
	return info, nil
}

func canonical(rec Record) ([]byte, error) {
	p := payload{
		Seq:      rec.Seq,
		Time:     rec.Time,
		Type:     rec.Type,
		Target:   rec.Target,
		Source:   rec.Source,
		PrevHash: rec.PrevHash,
		Data:     rec.Data,
	}
	return marshalCanonical(p)
}

// marshalCanonical produces the exact bytes that are hashed. encoding/json
// sorts map keys and compacts RawMessage, so the same record always yields the
// same bytes. HTML escaping is disabled so the canonical form is plain JSON
// that other languages can reproduce.
func marshalCanonical(v any) ([]byte, error) { return marshalJSON(v) }

func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// VerifyReport is the outcome of checking a log.
type VerifyReport struct {
	File       string   `json:"file"`
	Records    int      `json:"records"`
	RootSHA256 string   `json:"root_sha256"`
	FileSHA256 string   `json:"file_sha256"`
	OK         bool     `json:"ok"`
	Errors     []string `json:"errors,omitempty"`
}

// VerifyFile checks a JSONL evidence log for content integrity and chain
// continuity, and returns the recomputed root and file hashes.
func VerifyFile(path string) (*VerifyReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	rep, err := verify(io.TeeReader(f, h), path)
	if err != nil {
		return nil, err
	}
	rep.FileSHA256 = hex.EncodeToString(h.Sum(nil))
	return rep, nil
}

func verify(r io.Reader, name string) (*VerifyReport, error) {
	rep := &VerifyReport{File: name, OK: true}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)

	var prev string
	seq := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		seq++

		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			rep.failf("line %d: not valid JSON: %v", seq, err)
			continue
		}
		if rec.Seq != seq {
			rep.failf("line %d: sequence is %d, expected %d", seq, rec.Seq, seq)
		}
		if rec.PrevHash != prev {
			rep.failf("line %d: previous hash %s does not match %s", seq, short(rec.PrevHash), short(prev))
		}
		if !json.Valid(rec.Data) {
			rep.failf("line %d: data is not valid JSON", seq)
		}
		canon, err := canonical(rec)
		if err != nil {
			rep.failf("line %d: cannot canonicalise: %v", seq, err)
			continue
		}
		sum := sha256.Sum256(canon)
		want := hex.EncodeToString(sum[:])
		if rec.Hash != want {
			rep.failf("line %d: hash mismatch (record says %s, content hashes to %s)", seq, short(rec.Hash), short(want))
		}
		prev = rec.Hash
		rep.Records++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	rep.RootSHA256 = prev
	if rep.Records == 0 {
		rep.failf("log contains no records")
	}
	return rep, nil
}

func (r *VerifyReport) failf(format string, args ...any) {
	r.OK = false
	if len(r.Errors) < 20 {
		r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	}
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "..."
}
