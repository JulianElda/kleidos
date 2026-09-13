package vault

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
)

const (
	writers  = 50
	fullRuns = 20
)

func runs(t *testing.T) int {
	if testing.Short() {
		return 2
	}
	return fullRuns
}

// concurrentWrites launches n writers against dir, each setting its own key, and
// returns how many of the n keys survived. Every writer opens its own Store, the
// way separate processes would.
func concurrentWrites(t *testing.T, dir string, n int, update func(*Store, func(*Vault) error) error) int {
	t.Helper()

	var wg sync.WaitGroup
	start := make(chan struct{})
	errCh := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := Open(dir)
			if err != nil {
				errCh <- err
				return
			}
			key := fmt.Sprintf("K%03d", i)
			<-start // release them together, to maximise contention
			if err := update(s, func(v *Vault) error { return v.Set(key, "v") }); err != nil {
				errCh <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errCh)

	// The broken-lock variant surfaces some failures loudly, as `link: file
	// exists` -- those writers at least failed visibly, while the rest lost
	// silently. Record them without failing: silent loss is what the count measures.
	var failures int
	for err := range errCh {
		failures++
		t.Logf("writer failed: %v", err)
	}
	if failures > 0 {
		t.Logf("%d/%d writers returned an error", failures, n)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Load()
	if err != nil {
		t.Fatalf("vault unreadable after concurrent writes: %v", err)
	}
	return len(v.Secrets)
}

// TestConcurrentWritersLoseNothing is the load-bearing test for the write path.
// One green run proves nothing -- it is a race -- so this runs the whole thing 20
// times and requires every run to be perfect.
func TestConcurrentWritersLoseNothing(t *testing.T) {
	n := runs(t)
	for run := range n {
		dir := scratchDir(t)
		writeKeys(t, dir, 1)

		got := concurrentWrites(t, dir, writers, (*Store).Update)
		if got != writers {
			t.Fatalf("run %d/%d: kept %d of %d keys", run+1, n, got, writers)
		}
		if leftover := tempFiles(t, dir); len(leftover) != 0 {
			t.Fatalf("run %d/%d: leftover temp files: %v", run+1, n, leftover)
		}
	}
}

// brokenUpdate is Update with one difference: it unlinks the lock file after
// releasing it. This is the mistake the real implementation exists to avoid, and
// it lives here rather than in the shipped code.
//
// flock locks an inode, not a path. Once one writer unlinks the lock, the next
// O_CREAT produces a fresh inode, and two writers then hold exclusive locks on
// different objects -- excluding nobody, and losing each other's writes.
func (s *Store) brokenUpdate(fn func(*Vault) error) error {
	lf, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		_ = lf.Close()
		return err
	}
	err = func() error {
		v, err := s.load()
		if err != nil {
			return err
		}
		if v == nil {
			if v, err = New(); err != nil {
				return err
			}
		}
		if err := fn(v); err != nil {
			return err
		}
		return s.save(v)
	}()
	_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	_ = lf.Close()
	_ = os.Remove(s.lockPath()) // the bug under test
	return err
}

// TestBrokenLockActuallyLoses confirms the lock is load-bearing on this
// filesystem rather than assuming it. If this ever stops losing writes, that is
// worth knowing: it would mean the concurrency test above proves less than it
// appears to.
func TestBrokenLockActuallyLoses(t *testing.T) {
	// This machine loses on roughly half of runs rather than on every run, so the
	// control needs the full run count to be reliable. At two runs it reports a
	// false pass often enough to be worse than not running.
	if testing.Short() {
		t.Skip("the broken-lock control needs the full run count; it loses in " +
			"roughly half of runs on this machine, not all of them")
	}
	n := fullRuns
	worst := writers
	lost := 0

	for range n {
		dir := scratchDir(t)
		writeKeys(t, dir, 1)

		got := concurrentWrites(t, dir, writers, (*Store).brokenUpdate)
		if got < writers {
			lost++
			if got < worst {
				worst = got
			}
		}
	}

	t.Logf("broken lock lost writes in %d of %d runs; worst run kept %d of %d", lost, n, worst, writers)
	if lost == 0 {
		t.Errorf("the broken-lock variant kept all %d keys in all %d runs. The "+
			"lock's necessity is therefore unproven here, and the concurrency "+
			"test above may be passing for the wrong reason.", writers, n)
	}
}

// TestReadsAreNeverTorn exercises the decision that reads take no lock. rename is
// atomic, so a reader opens either the old inode or the new one, whole.
func TestReadsAreNeverTorn(t *testing.T) {
	dir := scratchDir(t)
	writeKeys(t, dir, 1)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(v *Vault) error { return v.Set("SEED", "0") }); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			w, err := Open(dir)
			if err != nil {
				t.Error(err)
				return
			}
			if err := w.Update(func(v *Vault) error {
				return v.Set("SEED", fmt.Sprintf("%d", i))
			}); err != nil {
				t.Error(err)
				return
			}
		}
		close(done)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		reads := 0
		for {
			select {
			case <-done:
				t.Logf("completed %d unlocked reads during concurrent writes", reads)
				return
			default:
			}
			r, err := Open(dir)
			if err != nil {
				t.Error(err)
				return
			}
			v, err := r.Load()
			if err != nil {
				t.Errorf("torn or unreadable vault during concurrent write: %v", err)
				return
			}
			if _, ok := v.Get("SEED"); !ok {
				t.Error("read a vault missing SEED")
				return
			}
			reads++
		}
	}()

	wg.Wait()
}
