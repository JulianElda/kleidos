package cmd

import (
	"fmt"
	"strings"

	"kleidos/internal/errs"
	"kleidos/internal/vault"
)

const hasUsage = `usage: kleidos has KEY [KEY...]

Answers "does the vault hold the secrets I need?". Nothing is printed on
success and the answer is the exit status, so this drops straight into a shell
if, and an agent needs no output parsing at all to act on it.

Absent keys are named on stderr -- all of them -- with the same message and the
same exit status (121) that "run" gives for a missing key, so a caller reads one
format for both. stdout stays empty, which is what keeps this verb free of
plaintext and free of an approval prompt.

A missing vault is exit 122, not 121: an unreadable vault is a different
condition from a key that is not in it, and a caller that treats the two alike
will provision over a vault it simply failed to open.

This reports storage, not usability. A value stored before empty values were
refused is reported present here and refused by "run"; re-set it or delete it.

Related: "run --optional" when the answer only decides whether to inject a key,
and "list --names" when the question is what the vault holds.`

func Has(args []string) error {
	keys, err := parseFlags("has", hasUsage, args, nil)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("has needs at least one key\n%s", hasUsage)
	}
	// A name that cannot be stored can never be present, so it is an error
	// rather than a silent "absent" -- which a caller would read as the
	// legitimate state it is not.
	for _, k := range keys {
		if err := vault.CheckKey(k); err != nil {
			return err
		}
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	v, err := s.Load()
	if err != nil {
		return err
	}
	if missing := v.Missing(keys); len(missing) > 0 {
		return fmt.Errorf("%w: %s", errs.ErrKeyNotFound, strings.Join(missing, ", "))
	}
	return nil
}
