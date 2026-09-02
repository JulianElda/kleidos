package cmd

import (
	"fmt"
	"text/tabwriter"
	"time"
)

const listUsage = `usage: kleidos list

Prints every key with its update time and a fingerprint of its value. No
plaintext is printed, so this needs no approval.

The fingerprint is HMAC-SHA256(fpkey, value) truncated to 8 hex characters, keyed
by a secret stored inside the vault. It is meaningless to anyone who cannot
already decrypt the vault, which is the point: it confirms that two machines hold
the same value, or that a write landed, without being a brute-forceable digest of
a low-entropy secret.

Listing requires the identity: all metadata lives inside the ciphertext.`

func List(args []string) error {
	rest, err := parseFlags("list", listUsage, args, nil)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("list takes no arguments\n%s", listUsage)
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	v, err := s.Load()
	if err != nil {
		return err
	}

	names := v.Names()
	if len(names) == 0 {
		return nil
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tUPDATED\tFINGERPRINT")
	for _, name := range names {
		secret, _ := v.Get(name)
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name,
			secret.Updated.UTC().Format(time.RFC3339),
			v.Fingerprint(secret.Value))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
