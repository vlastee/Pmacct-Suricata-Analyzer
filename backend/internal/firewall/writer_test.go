package firewall

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

type fakeStore struct {
	mu      sync.Mutex
	batches [][]db.FirewallEvent
	err     error
}

func (f *fakeStore) InsertFirewallEvents(_ context.Context, evs []db.FirewallEvent) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.batches = append(f.batches, append([]db.FirewallEvent(nil), evs...))
	return int64(len(evs)), nil
}

func (f *fakeStore) rows() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

const fwLine = `<134>1 2026-11-23T15:06:09.738675-05:00 pfSense.home.arpa filterlog 33866 - - 1,6,,1000000103,vtnet1,match,block,in,4,0x0,,64,7997,0,DF,6,tcp,52,10.0.0.112,192.0.2.80,58262,80,0,FA,2251152083,2471410537,1024,,nop;nop;TS`

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("timed out")
}

func TestWriterBatchesAndFlushes(t *testing.T) {
	st := &fakeStore{}
	w := &Writer{Store: st, BatchSize: 3, FlushEvery: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	for range 7 {
		if !w.Handle(fwLine) {
			t.Fatal("filterlog line not claimed")
		}
	}
	// Two full batches at once, the 7th row on the timer.
	waitFor(t, func() bool { return st.rows() == 7 })
	if s := w.Stats(); s.Received != 7 || s.Stored != 7 || s.LastEvent == nil {
		t.Errorf("stats %+v", s)
	}
	// Rows still queued at shutdown are flushed, not lost.
	w.Handle(fwLine)
	cancel()
	<-done
	if st.rows() < 7 {
		t.Errorf("lost rows: %d", st.rows())
	}
}

func TestWriterClaimsOnlyFilterlog(t *testing.T) {
	w := &Writer{Store: &fakeStore{}}
	if w.Handle(`<141>1 2026-11-23T14:57:11-05:00 pfSense suricata 4412 - - {"event_type":"tls"}`) {
		t.Error("claimed a Suricata line")
	}
	if w.Handle(`<134>1 2026-11-23T14:57:17-05:00 pfSense haproxy 1 - - backend filterlog_api is up`) {
		t.Error("claimed a line that only mentions filterlog")
	}
	if !w.Handle(`<134>1 2026-11-23T15:00:00-05:00 pfSense filterlog 1 - - not,a,record`) {
		t.Error("broken filterlog line should still be claimed")
	}
	if s := w.Stats(); s.Malformed != 1 || s.Received != 0 {
		t.Errorf("stats %+v", s)
	}
}

func TestWriterCountsOverflowAndFailures(t *testing.T) {
	st := &fakeStore{err: errors.New("db down")}
	w := &Writer{Store: st, QueueSize: 2, BatchSize: 10, FlushEvery: 20 * time.Millisecond}
	for range 5 {
		w.Handle(fwLine)
	}
	if s := w.Stats(); s.Overflow != 3 || s.Queued != 2 {
		t.Fatalf("overflow: %+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	waitFor(t, func() bool { return w.Stats().Failed == 2 })
	if s := w.Stats(); s.LastError != "db down" || s.Stored != 0 {
		t.Errorf("failure stats %+v", s)
	}
}
