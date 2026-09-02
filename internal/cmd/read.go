package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"kleidos/internal/errs"
	"kleidos/internal/vault"
)

// lookup loads the vault and resolves every key, all or nothing.
//
// A partial read is the dangerous outcome: returning a username with an empty
// password is worse than returning nothing, so any miss fails the whole call and
// names every absent key at once.
func lookup(keys []string) (*vault.Vault, []*vault.Secret, error) {
	s, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	v, err := s.Load()
	if err != nil {
		return nil, nil, err
	}
	if missing := v.Missing(keys); len(missing) > 0 {
		return nil, nil, fmt.Errorf("%w: %s", errs.ErrKeyNotFound, strings.Join(missing, ", "))
	}

	secrets := make([]*vault.Secret, len(keys))
	for i, k := range keys {
		// Present with an empty value is a distinct, legitimate state.
		secrets[i], _ = v.Get(k)
	}
	return v, secrets, nil
}

// emit writes values for human consumption: a lone value verbatim, or KEY=value
// lines when several were requested.
//
// The trailing newline makes a single value readable in a terminal, which is what
// this format is for. `reveal -0` is the byte-exact path.
func emit(w io.Writer, keys []string, secrets []*vault.Secret) error {
	bw := bufio.NewWriter(w)
	for i, k := range keys {
		if len(keys) > 1 {
			if _, err := bw.WriteString(k + "="); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		}
		if _, err := bw.WriteString(secrets[i].Value); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		if err := bw.WriteByte('\n'); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	// A silently truncated secret is worse than none, so the flush error is
	// checked rather than deferred away.
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// emitNUL writes NUL-delimited values in request order.
//
// This is the machine-readable path, not a niche flag: K=$(kleidos reveal FOO)
// silently eats trailing newlines, and certificate and key material is exactly
// the category that has them. NUL is guaranteed absent from values by the
// write-time rejection, which is what makes it a safe delimiter.
func emitNUL(w io.Writer, secrets []*vault.Secret) error {
	bw := bufio.NewWriter(w)
	for _, s := range secrets {
		if _, err := bw.WriteString(s.Value); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		if err := bw.WriteByte(0); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// stdout is indirected for tests.
var stdout io.Writer = os.Stdout
