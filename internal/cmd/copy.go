package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"kleidos/internal/clipboard"
	"kleidos/internal/errs"
)

const copyUsage = `usage: kleidos copy KEY [--clear-after DURATION]

Puts one value on the clipboard, then clears it. Terminal only, like "get":
this is for a human about to paste, not for a program.

  --clear-after DURATION   how long the value stays pasteable (default 45s)

The value is copied byte-exact, with no newline added, and offered with the
password-manager hint, so clipboard managers that honour it keep it out of
their history. Copying something else before the deadline ends it early.

Linux only, with nothing to install: kleidos speaks the display server's
protocol itself -- Wayland data-control where the compositor has it, X11
(including XWayland) otherwise. A background kleidos process holds the value
until the deadline, because the Linux clipboard is owned by a live client,
not stored by the system.`

// ServeVerb is the hidden verb the background half of "copy" runs under. It is
// not in the usage text: it reads the value from stdin, so it can hand out
// nothing its caller did not already have.
const ServeVerb = "__copy-serve"

const (
	defaultClearAfter = 45 * time.Second
	spawnTimeout      = 10 * time.Second
)

func Copy(args []string) error {
	var clearAfter *time.Duration
	keys, err := parseFlags("copy", copyUsage, args, func(f *flag.FlagSet) {
		clearAfter = f.Duration("clear-after", defaultClearAfter, "how long the value stays pasteable")
	})
	if err != nil {
		return err
	}
	if len(keys) != 1 {
		return fmt.Errorf("copy takes exactly one key\n%s", copyUsage)
	}
	if *clearAfter <= 0 {
		return fmt.Errorf("--clear-after must be positive; a clipboard that never clears is what this verb exists to avoid")
	}

	// The same gate as get, for a sharper reason: the clipboard is readable by
	// every process in the session, so a copied value is a plaintext dump that
	// merely skipped the transcript. An agent that could run this could run
	// wl-paste straight after.
	if !isTerminal(os.Stderr) {
		return fmt.Errorf("%w: refusing to copy plaintext to the clipboard", errs.ErrNoTerminal)
	}

	secrets, err := lookup(keys)
	if err != nil {
		return err
	}
	if err := spawnServer([]byte(secrets[0].Value), *clearAfter); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "copied %s; clears in %s\n", keys[0], *clearAfter)
	return nil
}

// spawnServer starts the background half and returns once it holds the
// clipboard, or with the reason it could not. Indirected for tests.
//
// Go cannot fork, so this re-executes the running binary. The value travels on
// the child's stdin -- not argv, which is world-readable, and not environ,
// which every grandchild would inherit -- and the child reports on fd 3 before
// this process exits, so "copied" is never printed for a copy that failed.
var spawnServer = func(value []byte, clearAfter time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating kleidos to run the clipboard server: %w", err)
	}
	valueR, valueW, err := os.Pipe()
	if err != nil {
		return err
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		_ = valueR.Close()
		_ = valueW.Close()
		return err
	}
	defer func() { _ = statusR.Close() }()

	c := exec.Command(exe, ServeVerb, clearAfter.String())
	c.Stdin = valueR
	c.ExtraFiles = []*os.File{statusW}
	c.Dir = "/" // hold no directory busy for the lifetime of the copy
	// Its own session: closing the terminal must not take the clipboard with
	// it, and a Ctrl-C meant for the shell's next command must not either.
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = c.Start()
	_ = valueR.Close()
	_ = statusW.Close()
	if err != nil {
		_ = valueW.Close()
		return fmt.Errorf("starting the clipboard server: %w", err)
	}

	// A write error means the child died early; its status says why.
	_, _ = valueW.Write(value)
	_ = valueW.Close()

	// A display server that accepts the connection and never answers would
	// otherwise hang the user's shell; the handshake takes milliseconds.
	_ = statusR.SetReadDeadline(time.Now().Add(spawnTimeout))
	status, err := io.ReadAll(statusR)
	if string(status) == serveReady {
		return c.Process.Release()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		_ = c.Process.Kill()
		_ = c.Wait()
		return fmt.Errorf("the clipboard server did not take the clipboard within %s", spawnTimeout)
	}
	_ = c.Wait()
	if len(status) == 0 {
		return errors.New("the clipboard server exited without reporting")
	}
	return fmt.Errorf("copying to the clipboard: %s", status)
}

// serveReady is the whole success message on the status pipe; anything else
// is an error message.
const serveReady = "ok"

// CopyServe is the background half of copy. It must be started by spawnServer:
// the value on stdin, the status pipe on fd 3.
func CopyServe(args []string) error {
	if len(args) != 1 {
		return errors.New(ServeVerb + " is internal; use kleidos copy")
	}
	clearAfter, err := time.ParseDuration(args[0])
	if err != nil || clearAfter <= 0 {
		return errors.New(ServeVerb + " is internal; use kleidos copy")
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(3, &st); err != nil {
		return errors.New(ServeVerb + " is internal; use kleidos copy")
	}
	return serveCopy(os.Stdin, os.NewFile(3, "status"), clearAfter)
}

// serveClipboard is indirected for tests.
var serveClipboard = clipboard.Serve

// serveCopy reads the value, holds the clipboard for clearAfter, and reports
// on status exactly once: ready as soon as the clipboard is held, or the error
// that prevented it.
func serveCopy(in io.Reader, status io.WriteCloser, clearAfter time.Duration) error {
	value, err := io.ReadAll(in)
	if err != nil {
		_, _ = io.WriteString(status, "reading the value: "+err.Error())
		_ = status.Close()
		return err
	}

	// The deadline starts at the spawn rather than at ownership. The
	// difference is the connection setup, and a bound measured from the
	// user's keypress is the one they can reason about.
	ctx, cancel := context.WithTimeout(context.Background(), clearAfter)
	defer cancel()

	reported := false
	err = serveClipboard(ctx, value, func() {
		_, _ = io.WriteString(status, serveReady)
		_ = status.Close()
		reported = true
	})
	if !reported {
		if err == nil {
			err = errors.New("the clipboard was released before it was confirmed")
		}
		_, _ = io.WriteString(status, err.Error())
		_ = status.Close()
	}
	return err
}
