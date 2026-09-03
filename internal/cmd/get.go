package cmd

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"kleidos/internal/errs"
)

const getUsage = `usage: kleidos get KEY [KEY...]

Prints values, but only when stderr is a terminal. There is no flag that
overrides this; the override is a different command, "kleidos reveal".

With one key the value is printed verbatim; with several, as KEY=value lines.
Either way a trailing newline is added, so use "reveal -0" when the exact bytes
matter.

If any key is missing, nothing is printed and every missing name is reported.`

func Get(args []string) error {
	keys, err := parseFlags("get", getUsage, args, nil)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("get needs at least one key\n%s", getUsage)
	}

	// Gate on stderr, not stdout.
	//
	// Under an agent harness all three standard descriptors are non-TTY, so
	// stderr is a terminal exactly when a human one is present, independent of
	// what stdout is doing. That means `get FOO > file` and `get FOO | pbcopy`
	// work for a human at a terminal while a captured invocation still refuses.
	//
	// Scope, precisely: this stops accidents, not intent. An agent that wants the
	// value runs `reveal`, or allocates a pty, and both work. The property worth
	// having is that plaintext does not reach a transcript by default, and that
	// putting it there is a distinct, promptable act.
	if !isTerminal(os.Stderr) {
		return fmt.Errorf("%w: refusing to print plaintext (use `kleidos reveal` to dump it deliberately)", errs.ErrNoTerminal)
	}

	secrets, err := lookup(keys)
	if err != nil {
		return err
	}
	return emit(stdout, keys, secrets)
}

// isTerminal is indirected for tests.
var isTerminal = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
