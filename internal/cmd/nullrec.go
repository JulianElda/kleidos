package cmd

import (
	"fmt"
	"io"
	"strings"

	"kleidos/internal/vault"
)

// parseNullRecords reads NUL-delimited KEY=value records.
//
// This is the format for generated input, and the .env subset stays the format
// for human input. The two are not interchangeable: a program handing over
// values it cannot regenerate -- credentials returned once by a provisioning
// call, say -- must not have its import refused because an upstream tool left a
// trailing space in a field, since the fallback for a refused import is writing
// the plaintext somewhere, which is the thing the pipe existed to avoid.
//
// So there is nothing in this grammar to get wrong. NUL delimits records
// precisely because it is the one byte no stored value may contain, which is
// enforced at every write path; there is therefore no escaping, and no value can
// be mis-split. Everything after the first = is the value, verbatim: no quote
// stripping, no whitespace trimming, no comments, no continuations, and newlines
// inside a value are ordinary bytes.
func parseNullRecords(r io.Reader) ([]entry, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	if len(data) == 0 {
		return nil, nil // import reports the empty input; the parser has no opinion
	}

	// A trailing delimiter after the final record is what a generator naturally
	// emits, and what `reveal -0` emits, so it terminates the last record rather
	// than opening an empty one.
	body := strings.TrimSuffix(string(data), "\x00")

	var entries []entry
	seen := map[string]string{}
	for i, rec := range strings.Split(body, "\x00") {
		loc := fmt.Sprintf("record %d", i+1)
		if rec == "" {
			return nil, fmt.Errorf("%s: empty record", loc)
		}
		eq := strings.IndexByte(rec, '=')
		if eq < 0 {
			return nil, fmt.Errorf("%s: not a KEY=value record", loc)
		}
		key, value := rec[:eq], rec[eq+1:]
		if err := vault.CheckKey(key); err != nil {
			return nil, fmt.Errorf("%s: %w", loc, err)
		}
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("%s: duplicate key %s, already assigned in %s", loc, key, prev)
		}
		seen[key] = loc
		entries = append(entries, entry{key: key, value: value, loc: loc})
	}
	return entries, nil
}
