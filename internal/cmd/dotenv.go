package cmd

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"kleidos/internal/vault"
)

// entry is one parsed assignment, in input order.
//
// loc is where it came from, already formatted -- "line 3" for .env input,
// "record 3" for NUL-delimited input -- so that a caller reporting a problem
// with an entry does not have to know which parser produced it.
type entry struct {
	key   string
	value string
	loc   string
}

// parseDotenv accepts a strict subset of .env and rejects everything else
// loudly, naming the line.
//
// Strictness is the whole point: a silently mis-parsed value stored as a secret
// is discovered at the worst possible moment. A .env file is data, not a script,
// so no expansion of any kind is performed in either quote style -- no $VAR, no
// \n unescaping, no command substitution.
//
// Accepted:
//   - KEY=value, optionally prefixed with "export "
//   - blank lines
//   - # comments on their own line
//   - values wrapped in matching single or double quotes, stripped on read
//
// Everything else is an error: trailing comments, line continuations, multi-line
// values, unmatched quotes, spaces around =, NUL, CRLF, duplicate keys.
func parseDotenv(r io.Reader) ([]entry, error) {
	var entries []entry
	seen := map[string]int{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for n := 1; sc.Scan(); n++ {
		raw := sc.Text()

		if strings.IndexByte(raw, 0) >= 0 {
			return nil, fmt.Errorf("line %d: contains a NUL byte", n)
		}
		// bufio.ScanLines already drops one trailing \r, so ordinary CRLF files
		// parse cleanly. Anything left is an interior or doubled carriage return,
		// which would otherwise end up inside the value.
		if strings.IndexByte(raw, '\r') >= 0 {
			return nil, fmt.Errorf("line %d: stray carriage return; it would become part of the value", n)
		}

		trimmed := strings.TrimLeft(raw, " \t")
		if trimmed == "" {
			continue
		}
		// Comments are recognised only on their own line. A trailing comment --
		// PASS=hunter2 # prod -- has no correct reading, and guessing produces
		// either a wrong value or a wrong comment.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, `\`) {
			return nil, fmt.Errorf("line %d: line continuation is not supported; put the value on one line and quote it", n)
		}

		trimmed = strings.TrimPrefix(trimmed, "export ")
		trimmed = strings.TrimLeft(trimmed, " \t")

		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: not a KEY=value assignment", n)
		}
		key, rest := trimmed[:eq], trimmed[eq+1:]

		if key != strings.TrimRight(key, " \t") {
			return nil, fmt.Errorf("line %d: no spaces are allowed around =", n)
		}
		if err := vault.CheckKey(key); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %s, already assigned on line %d", n, key, prev)
		}

		// Once the key is known it goes into the diagnostic alongside the line.
		// For generated input the key name is the stable identifier and the line
		// number is noise -- worse than noise when the input was a pipe, since
		// the stream naming that line no longer exists by the time anyone reads
		// the message.
		value, err := parseValue(rest, fmt.Sprintf("line %d (%s)", n, key))
		if err != nil {
			return nil, err
		}

		seen[key] = n
		entries = append(entries, entry{key: key, value: value, loc: fmt.Sprintf("line %d", n)})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	return entries, nil
}

// parseValue handles the right-hand side of one assignment. at is the formatted
// location, key included, that every diagnostic here is prefixed with.
func parseValue(rest string, at string) (string, error) {
	if rest == "" {
		return "", nil
	}

	if q := rest[0]; q == '\'' || q == '"' {
		// No escaping is performed, so the first closing quote ends the value and
		// the quote character cannot appear inside it.
		end := strings.IndexByte(rest[1:], q)
		if end < 0 {
			return "", fmt.Errorf("%s: unmatched %c quote; multi-line values are not supported", at, q)
		}
		if tail := rest[end+2:]; tail != "" {
			return "", fmt.Errorf("%s: unexpected text after the closing quote: %q", at, tail)
		}
		return rest[1 : end+1], nil
	}

	// Unquoted values carry no delimiters, so anything ambiguous is refused
	// rather than guessed at. Quoting is the fix in every case.
	if strings.ContainsAny(rest, "\"'") {
		return "", fmt.Errorf("%s: unquoted value contains a quote character; wrap the whole value in quotes", at)
	}
	if strings.IndexByte(rest, '#') >= 0 {
		return "", fmt.Errorf("%s: unquoted value contains #, which could be a comment or part of the value; wrap the value in quotes", at)
	}
	if rest != strings.Trim(rest, " \t") {
		return "", fmt.Errorf("%s: unquoted value has leading or trailing whitespace; wrap the value in quotes if it is intended", at)
	}
	return rest, nil
}
