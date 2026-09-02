package cmd

import (
	"bytes"
	"strings"

	"kleidos/internal/errs"
)

// shellQuote wraps v in single quotes, escaping embedded single quotes as '\”.
//
// This is a shell injection surface, not a formatting detail: the output is
// eval'ed, so a bug here is arbitrary code execution.
//
// Single quotes suppress every form of expansion, which handles $, backticks,
// newlines and backslashes for free. The only byte that needs handling is the
// single quote itself, and '\” -- close, escaped literal quote, reopen -- is the
// only sequence that survives. Deliberately not printf %q, which is locale- and
// shell-dependent.
//
// The (string, error) signature is deliberate: as func([]byte) string the only
// options on a NUL would have been silent truncation or a panic.
func shellQuote(v []byte) (string, error) {
	if bytes.IndexByte(v, 0) >= 0 {
		return "", errs.ErrNUL
	}
	var sb strings.Builder
	sb.Grow(len(v) + 2)
	sb.WriteByte('\'')
	for _, c := range v {
		if c == '\'' {
			sb.WriteString(`'\''`)
		} else {
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('\'')
	return sb.String(), nil
}
