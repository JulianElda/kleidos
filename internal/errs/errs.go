// Package errs defines kleidos's error taxonomy and the exit codes it maps to.
//
// Codes live at 120-125 deliberately. The range 1-7 collides maximally with real
// programs -- psql returns 3, git returns 1/2/128, curl uses 1 through 92 -- and
// `kleidos run` execs a child whose status passes through unmodified. With this
// layout any code below 120 came from the child, and every code from 120 up is
// ours. 126, 127 and 128+n stay reserved for the shell conventions.
package errs

import (
	"errors"
	"fmt"
)

// Process exit statuses.
const (
	OK            = 0
	Generic       = 120
	KeyNotFound   = 121
	VaultNotFound = 122
	Identity      = 123
	Decrypt       = 124
	NoTerminal    = 125

	// Shell conventions, reserved. `run` follows them.
	NotExecutable = 126
	NotFound      = 127
)

var (
	ErrKeyNotFound   = errors.New("key not found")
	ErrVaultNotFound = errors.New("vault not found")
	ErrIdentity      = errors.New("identity missing or unreadable")
	ErrDecrypt       = errors.New("decryption failed")
	ErrNoTerminal    = errors.New("stderr is not a terminal")

	// ErrNUL is an invariant violation: `set` and `import` reject NUL at write
	// time so that every downstream consumer -- export, run, reveal -- can rely
	// on values being NUL-free rather than each re-checking.
	ErrNUL = errors.New("value contains NUL byte")
)

// Coded wraps an error with an explicit exit status, for the cases that are not
// covered by a sentinel -- notably `run` propagating 126 and 127.
type Coded struct {
	Status int
	Err    error
}

func (c *Coded) Error() string { return c.Err.Error() }
func (c *Coded) Unwrap() error { return c.Err }

// Codef builds a Coded error with a formatted message.
func Codef(status int, format string, a ...any) error {
	return &Coded{Status: status, Err: fmt.Errorf(format, a...)}
}

// Code maps err onto the process exit status.
func Code(err error) int {
	if err == nil {
		return OK
	}
	var c *Coded
	if errors.As(err, &c) {
		return c.Status
	}
	switch {
	case errors.Is(err, ErrKeyNotFound):
		return KeyNotFound
	case errors.Is(err, ErrVaultNotFound):
		return VaultNotFound
	case errors.Is(err, ErrIdentity):
		return Identity
	case errors.Is(err, ErrDecrypt):
		return Decrypt
	case errors.Is(err, ErrNoTerminal):
		return NoTerminal
	default:
		return Generic
	}
}
