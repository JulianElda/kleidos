package cmd

import (
	"bufio"
	"fmt"

	"kleidos/internal/vault"
)

const exportUsage = `usage: eval "$(kleidos export)"

Emits shell assignments for every secret. This is a deliberate plaintext dump.

There is no terminal check, and there cannot be one: command substitution makes
stdout a pipe unconditionally, including when a human types it, so any such check
would make the command useless for its only purpose. The gate is the permission
rule on this verb.

Use the quoted form above. Unquoted -- eval $(kleidos export) -- word-splits the
output and turns newlines inside values into spaces.`

func Export(args []string) error {
	rest, err := parseFlags("export", exportUsage, args, nil)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("export takes no arguments\n%s", exportUsage)
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	v, err := s.Load()
	if err != nil {
		return err
	}

	bw := bufio.NewWriter(stdout)
	for _, name := range v.Names() {
		// Validate names at emit time, not just on import. The left-hand side of
		// an eval'ed assignment is its own injection point, and trusting the blob
		// assumes every past write enforced the constraint.
		//
		// A bad name fails the whole export rather than skipping the entry: a
		// silently short export is how a caller ends up running with a missing
		// credential.
		if err := vault.CheckKey(name); err != nil {
			return fmt.Errorf("refusing to export: %w", err)
		}
		secret, _ := v.Get(name)
		quoted, err := shellQuote([]byte(secret.Value))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if _, err := fmt.Fprintf(bw, "export %s=%s\n", name, quoted); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
