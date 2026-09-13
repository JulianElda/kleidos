package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"golang.org/x/term"

	"kleidos/internal/vault"
)

const setUsage = `usage: kleidos set KEY [--stdin]

Stores a value under KEY, prompting on the terminal with echo off.

There is deliberately no positional value argument: argv is world-readable via
/proc/<pid>/cmdline.

  --stdin   read the value from standard input, verbatim. No trailing newline is
            stripped, since values such as certificates and keys legitimately end
            with one. Use printf %s, not echo, to avoid storing a stray newline.`

func Set(args []string) error {
	var stdin *bool
	rest, err := parseFlags("set", setUsage, args, func(f *flag.FlagSet) {
		stdin = f.Bool("stdin", false, "read the value from standard input")
	})
	if err != nil {
		return err
	}

	if len(rest) != 1 {
		return fmt.Errorf("set takes exactly one key\n%s", setUsage)
	}
	key := rest[0]
	if err := vault.CheckKey(key); err != nil {
		return err
	}

	var value []byte
	if *stdin {
		value, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading value from stdin: %w", err)
		}
	} else {
		value, err = prompt(key)
		if err != nil {
			return err
		}
	}
	// Best-effort: zero the buffer we control once it has been handed off.
	defer zero(value)

	if err := vault.CheckValue(string(value)); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	return s.Update(func(v *vault.Vault) error { return v.Set(key, string(value)) })
}

// prompt reads a value from the controlling terminal with echo off.
//
// It opens /dev/tty rather than using stdin, so that `kleidos set K < file` is a
// clear error rather than a silent read of the wrong thing.
func prompt(key string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("no terminal available to prompt on (use --stdin): %w", err)
	}
	defer func() { _ = tty.Close() }()

	fd := int(tty.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("reading terminal state: %w", err)
	}

	// A ^C during the prompt must not leave the terminal with echo off. This is
	// an easy bug to ship and a deeply annoying one to receive.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		<-sig
		_ = term.Restore(fd, state)
		_, _ = fmt.Fprintln(tty)
		os.Exit(130) // 128 + SIGINT, per the shell convention
	}()

	_, _ = fmt.Fprintf(tty, "value for %s: ", key)
	value, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		_ = term.Restore(fd, state)
		return nil, fmt.Errorf("reading value: %w", err)
	}
	return value, nil
}

// zero overwrites b. Best-effort only: the garbage collector may already have
// moved the data, and nothing here can undo that.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
