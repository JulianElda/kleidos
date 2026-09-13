// Package cmd implements the kleidos verbs. Each entry point takes the argument
// list following the verb and returns an error whose exit status errs.Code
// resolves.
package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"kleidos/internal/vault"
)

// openStore resolves the vault directory and loads the identity.
func openStore() (*vault.Store, error) {
	dir, err := vault.Dir()
	if err != nil {
		return nil, err
	}
	return vault.Open(dir)
}

// parseFlags parses args for a verb and returns its positional arguments.
//
// Flags may appear after positionals -- `kleidos set KEY --stdin` is the
// documented spelling, and the stdlib flag package stops at the first non-flag
// argument. Everything after a literal "--" is positional, never a flag.
func parseFlags(name, usage string, args []string, bind func(*flag.FlagSet)) ([]string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	if bind != nil {
		bind(fs)
	}

	var literal []string
	for i, a := range args {
		if a == "--" {
			literal, args = args[i+1:], args[:i]
			break
		}
	}

	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelp
			}
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	return append(positional, literal...), nil
}

// errHelp signals that usage was printed deliberately.
var errHelp = errors.New("help requested")

// IsHelp reports whether err came from an explicit -h.
func IsHelp(err error) bool { return errors.Is(err, errHelp) }
