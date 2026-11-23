package firewall

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Store is the database side of the writer (db.DB in production).
type Store interface {
	InsertFirewallEvents(ctx context.Context, evs []db.FirewallEvent) (int64, error)
}

// Writer parses filterlog lines and stores them in batches with COPY, so a busy firewall log
// (thousands of lines a minute) costs one round trip per batch instead of one per line.
type Writer struct {
	Store      Store
	BatchSize  int           // rows per COPY (default 1000)
	FlushEvery time.Duration // longest a row waits before it is written (default 2s)
	QueueSize  int           // parsed rows buffered ahead of the database (default 20000)
	Now        func() time.Time

	once     sync.Once
	ch       chan db.FirewallEvent
	received atomic.Int64 // filterlog lines seen
	stored   atomic.Int64
	bad      atomic.Int64 // filterlog lines that would not parse
	overflow atomic.Int64 // rows discarded because the queue was full
	failed   atomic.Int64 // rows lost to database errors
	lastWarn atomic.Int64

	mu        sync.Mutex
	lastAt    time.Time
	lastErr   string
	lastErrAt time.Time
}

// Stats is the writer snapshot shown on the IDS page.
type Stats struct {
	Received    int64      `json:"received"`
	Stored      int64      `json:"stored"`
	Malformed   int64      `json:"malformed"`
	Overflow    int64      `json:"overflow"`
	Failed      int64      `json:"failed"`
	Queued      int        `json:"queued"`
	LastEvent   *time.Time `json:"last_event,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

func (w *Writer) init() {
	w.once.Do(func() {
		if w.BatchSize <= 0 {
			w.BatchSize = 1000
		}
		if w.FlushEvery <= 0 {
			w.FlushEvery = 2 * time.Second
		}
		if w.QueueSize <= 0 {
			w.QueueSize = 20000
		}
		if w.Now == nil {
			w.Now = time.Now
		}
		w.ch = make(chan db.FirewallEvent, w.QueueSize)
	})
}

// Handle takes one syslog line. It returns false when the line is not from filterlog (the
// caller handles it), true otherwise, including filterlog lines that would not parse.
func (w *Writer) Handle(line string) bool {
	if !IsFilterlog(line) {
		return false
	}
	w.init()
	now := w.Now()
	e, ok := ParseLine(line, now)
	if !ok {
		if !rfc5424.MatchString(line) && !rfc3164.MatchString(line) {
			return false // mentions filterlog but is not a filterlog record
		}
		w.bad.Add(1)
		return true
	}
	w.received.Add(1)
	select {
	case w.ch <- e:
	default:
		w.overflow.Add(1)
		w.warn("firewall log queue full, dropping records", "overflow_total", w.overflow.Load())
	}
	return true
}

// Run writes queued records until ctx is done, then flushes what is left.
func (w *Writer) Run(ctx context.Context) {
	w.init()
	batch := make([]db.FirewallEvent, 0, w.BatchSize)
	tick := time.NewTicker(w.FlushEvery)
	defer tick.Stop()
	flush := func(ctx context.Context) {
		if len(batch) == 0 {
			return
		}
		n, err := w.Store.InsertFirewallEvents(ctx, batch)
		if err != nil {
			w.failed.Add(int64(len(batch)))
			w.mu.Lock()
			w.lastErr, w.lastErrAt = err.Error(), w.Now()
			w.mu.Unlock()
			w.warn("firewall log write failed", "rows", len(batch), "err", err)
		} else {
			w.stored.Add(n)
			w.mu.Lock()
			w.lastAt = batch[len(batch)-1].TS
			w.mu.Unlock()
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
		drain:
			for {
				select {
				case e := <-w.ch:
					batch = append(batch, e)
				default:
					break drain
				}
			}
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flush(fctx)
			cancel()
			return
		case e := <-w.ch:
			batch = append(batch, e)
			if len(batch) >= w.BatchSize {
				flush(ctx)
			}
		case <-tick.C:
			flush(ctx)
		}
	}
}

// warn logs at most once a minute.
func (w *Writer) warn(msg string, args ...any) {
	now := w.Now().Unix()
	if last := w.lastWarn.Load(); now-last >= 60 && w.lastWarn.CompareAndSwap(last, now) {
		slog.Warn(msg, args...)
	}
}

// Stats returns a snapshot.
func (w *Writer) Stats() Stats {
	w.init()
	s := Stats{Received: w.received.Load(), Stored: w.stored.Load(), Malformed: w.bad.Load(), Overflow: w.overflow.Load(),
		Failed: w.failed.Load(), Queued: len(w.ch)}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.lastAt.IsZero() {
		t := w.lastAt
		s.LastEvent = &t
	}
	if w.lastErr != "" {
		s.LastError = w.lastErr
		t := w.lastErrAt
		s.LastErrorAt = &t
	}
	return s
}
