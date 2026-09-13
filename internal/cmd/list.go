package cmd

import (
	"bufio"
	"flag"
	"fmt"
	"text/tabwriter"
	"time"
)

const listUsage = `usage: kleidos list [--names]

Prints every key with its update time and a fingerprint of its value. No
plaintext is printed, so this needs no approval.

The fingerprint is HMAC-SHA256(fpkey, value) truncated to 8 hex characters, keyed
by a secret stored inside the vault. It is meaningless to anyone who cannot
already decrypt the vault, which is the point: it confirms that two machines hold
the same value, or that a write landed, without being a brute-forceable digest of
a low-entropy secret.

Listing requires the identity: all metadata lives inside the ciphertext.

  --names   print bare key names, one per line, with no header

The table is human output: its columns are not a contract and may gain more. A
program that needs to know what the vault holds reads --names, which is one.
Answering "do these particular keys exist" is "has", which needs no parsing at
all.`

func List(args []string) error {
	var names *bool
	rest, err := parseFlags("list", listUsage, args, func(f *flag.FlagSet) {
		names = f.Bool("names", false, "print bare key names, one per line")
	})
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

	keys := v.Names()
	if len(keys) == 0 {
		return nil
	}

	if *names {
		bw := bufio.NewWriter(stdout)
		for _, name := range keys {
			if _, err := fmt.Fprintln(bw, name); err != nil {
				return fmt.Errorf("writing output: %w", err)
			}
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tUPDATED\tFINGERPRINT"); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	for _, name := range keys {
		secret, _ := v.Get(name)
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", name,
			secret.Updated.UTC().Format(time.RFC3339),
			v.Fingerprint(secret.Value)); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
