package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"kleidos/internal/errs"
)

// spawned replaces the background half with a recorder, so no test touches a
// real clipboard. It returns what the verb handed over, if anything.
func spawned(t *testing.T) *[]spawn {
	t.Helper()
	var calls []spawn
	old := spawnServer
	spawnServer = func(value []byte, clearAfter time.Duration) error {
		calls = append(calls, spawn{string(value), clearAfter})
		return nil
	}
	t.Cleanup(func() { spawnServer = old })
	return &calls
}

type spawn struct {
	value      string
	clearAfter time.Duration
}

func TestCopyRefusesWithoutTerminalOnStderr(t *testing.T) {
	seed(t, "DB_PASSWORD", "hunter2")
	asTerminal(t, false)
	calls := spawned(t)

	err := Copy([]string{"DB_PASSWORD"})
	if !errors.Is(err, errs.ErrNoTerminal) || errs.Code(err) != errs.NoTerminal {
		t.Fatalf("want ErrNoTerminal (exit %d), got %v", errs.NoTerminal, err)
	}
	if len(*calls) != 0 {
		t.Fatal("a refused copy still reached the clipboard")
	}
}

// Byte-exact, unlike get: nothing is added, and a trailing newline the value
// really has is kept. Pasting a password with a stray newline submits a form.
func TestCopyHandsOverTheExactValue(t *testing.T) {
	seed(t, "TLS_KEY", "-----BEGIN-----\nabc\n")
	asTerminal(t, true)
	calls := spawned(t)

	if err := Copy([]string{"TLS_KEY"}); err != nil {
		t.Fatal(err)
	}
	want := []spawn{{"-----BEGIN-----\nabc\n", defaultClearAfter}}
	if len(*calls) != 1 || (*calls)[0] != want[0] {
		t.Fatalf("spawned %+v, want %+v", *calls, want)
	}
}

func TestCopyPassesClearAfterThrough(t *testing.T) {
	seed(t, "DB_PASSWORD", "hunter2")
	asTerminal(t, true)
	calls := spawned(t)

	if err := Copy([]string{"DB_PASSWORD", "--clear-after", "10s"}); err != nil {
		t.Fatal(err)
	}
	if (*calls)[0].clearAfter != 10*time.Second {
		t.Fatalf("clear-after = %s, want 10s", (*calls)[0].clearAfter)
	}
}

func TestCopyRefusesAClipboardThatNeverClears(t *testing.T) {
	seed(t, "DB_PASSWORD", "hunter2")
	asTerminal(t, true)
	calls := spawned(t)

	for _, d := range []string{"0s", "-5s"} {
		if err := Copy([]string{"DB_PASSWORD", "--clear-after", d}); err == nil {
			t.Errorf("--clear-after %s was accepted", d)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("an invalid copy reached the clipboard")
	}
}

// A clipboard holds one value, so several keys have no meaning to guess at.
func TestCopyTakesExactlyOneKey(t *testing.T) {
	seed(t, "DB_USER", "alice", "DB_PASSWORD", "hunter2")
	asTerminal(t, true)
	calls := spawned(t)

	for _, args := range [][]string{{}, {"DB_USER", "DB_PASSWORD"}} {
		if err := Copy(args); err == nil {
			t.Errorf("copy %v was accepted", args)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("an invalid copy reached the clipboard")
	}
}

func TestCopyOfAnAbsentKeyIsKeyNotFound(t *testing.T) {
	seed(t, "DB_USER", "alice")
	asTerminal(t, true)
	calls := spawned(t)

	err := Copy([]string{"DB_PASSWORD"})
	if errs.Code(err) != errs.KeyNotFound {
		t.Fatalf("want exit %d, got %v", errs.KeyNotFound, err)
	}
	if len(*calls) != 0 {
		t.Fatal("copy of an absent key reached the clipboard")
	}
}

// statusPipe records what the background half reports to its parent.
type statusPipe struct {
	strings.Builder
	closes int
}

func (s *statusPipe) Close() error { s.closes++; return nil }

func withServe(t *testing.T, fn func(context.Context, []byte, func()) error) {
	t.Helper()
	old := serveClipboard
	serveClipboard = fn
	t.Cleanup(func() { serveClipboard = old })
}

// The parent prints "copied" on the strength of this report, so ready has to
// go out as soon as ownership is held -- not when serving ends 45s later.
func TestServeCopyReportsReadyWhileStillServing(t *testing.T) {
	var status statusPipe
	var sawReady bool
	withServe(t, func(ctx context.Context, value []byte, ready func()) error {
		if string(value) != "hunter2\n" {
			t.Errorf("served %q", value)
		}
		ready()
		sawReady = status.String() == serveReady && status.closes == 1
		return nil
	})

	if err := serveCopy(strings.NewReader("hunter2\n"), &status, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !sawReady {
		t.Fatal("ready was not reported, closed, before serving finished")
	}
	if status.String() != serveReady || status.closes != 1 {
		t.Fatalf("status %q closed %d times after serving", status.String(), status.closes)
	}
}

func TestServeCopyReportsWhyTheClipboardWasNotTaken(t *testing.T) {
	var status statusPipe
	withServe(t, func(context.Context, []byte, func()) error {
		return errors.New("no usable clipboard")
	})

	if err := serveCopy(strings.NewReader("hunter2"), &status, time.Minute); err == nil {
		t.Fatal("want the backend error")
	}
	if status.String() != "no usable clipboard" || status.closes != 1 {
		t.Fatalf("status %q closed %d times", status.String(), status.closes)
	}
}

func TestServeCopyClearsAtTheDeadline(t *testing.T) {
	var status statusPipe
	withServe(t, func(ctx context.Context, _ []byte, ready func()) error {
		ready()
		<-ctx.Done()
		return nil
	})

	start := time.Now()
	if err := serveCopy(strings.NewReader("hunter2"), &status, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("served for %s past a 50ms deadline", elapsed)
	}
}
