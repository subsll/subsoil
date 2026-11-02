package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinner is a one-line terminal activity indicator. It is safe to pause from
// the logger while a normal log line is being written.
type spinner struct {
	mu       sync.Mutex
	w        io.Writer
	label    string
	p        painter
	interval time.Duration
	start    time.Time
	frame    int
	paused   bool
	started  bool
	stopped  bool
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func newSpinner(w io.Writer, label string, color bool) *spinner {
	return &spinner{
		w:        w,
		label:    label,
		p:        painter{on: color},
		interval: 120 * time.Millisecond,
	}
}

func (s *spinner) Start() {
	if s == nil || s.w == nil {
		return
	}
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.start = time.Now()
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.drawLocked()
	s.mu.Unlock()
	go s.loop()
}

func (s *spinner) loop() {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			if !s.paused && !s.stopped {
				s.frame = (s.frame + 1) % len(spinnerFrames)
				s.drawLocked()
			}
			s.mu.Unlock()
		}
	}
}

func (s *spinner) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.started || s.stopped {
		s.stopped = true
		s.mu.Unlock()
		return
	}
	s.stopped = true
	stopCh, doneCh := s.stopCh, s.doneCh
	s.mu.Unlock()

	close(stopCh)
	<-doneCh

	s.mu.Lock()
	s.clearLocked()
	s.mu.Unlock()
}

// Pause clears the spinner line before a logger writes its own line.
func (s *spinner) Pause() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped || s.paused {
		return
	}
	s.paused = true
	s.clearLocked()
}

// Resume redraws the spinner after a logger line is complete.
func (s *spinner) Resume() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.stopped || !s.paused {
		return
	}
	s.paused = false
	s.drawLocked()
}

func (s *spinner) drawLocked() {
	frame := spinnerFrames[s.frame%len(spinnerFrames)]
	elapsed := formatSpinnerElapsed(time.Since(s.start))
	fmt.Fprintf(s.w, "\r\033[2K  %s %s  %s", frame, s.p.dim(s.label), s.p.dim(elapsed))
}

func (s *spinner) clearLocked() {
	fmt.Fprint(s.w, "\r\033[2K")
}

func formatSpinnerElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return fmt.Sprintf("%dm%02ds", int(d/time.Minute), int(d%time.Minute/time.Second))
}
