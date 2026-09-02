package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"kleidos/internal/vault"
)

const importUsage = `usage: kleidos import FILE

Loads a strict subset of .env. Anything outside that subset is an error naming
the line, because a silently mis-parsed value stored as a secret is discovered at
the worst possible moment.

No expansion is performed in either quote style: a .env file is data, not a
script.

If any key in the file already exists in the vault, nothing is imported and every
collision is listed. Either flag below is applied to the whole file or not at all
-- a half-applied import leaves the vault in a state nobody chose.

  --overwrite       replace the vault's version of every colliding key
  --skip-existing   keep the vault's version of every colliding key`

func Import(args []string) error {
	var overwrite, skip *bool
	rest, err := parseFlags("import", importUsage, args, func(f *flag.FlagSet) {
		overwrite = f.Bool("overwrite", false, "replace colliding keys")
		skip = f.Bool("skip-existing", false, "keep the vault's version of colliding keys")
	})
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("import takes exactly one file\n%s", importUsage)
	}
	if *overwrite && *skip {
		return fmt.Errorf("--overwrite and --skip-existing are mutually exclusive")
	}

	f, err := os.Open(rest[0])
	if err != nil {
		return fmt.Errorf("opening %s: %w", rest[0], err)
	}
	defer f.Close()

	entries, err := parseDotenv(f)
	if err != nil {
		return fmt.Errorf("%s: %w", rest[0], err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s: no assignments found", rest[0])
	}
	// The same write-time invariant as `set`: reject NUL here rather than
	// downstream, so every consumer can rely on values being NUL-free.
	for _, e := range entries {
		if err := vault.CheckValue(e.value); err != nil {
			return fmt.Errorf("%s: line %d: %s: %w", rest[0], e.line, e.key, err)
		}
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	return s.Update(func(v *vault.Vault) error {
		var colliding []string
		for _, e := range entries {
			if _, exists := v.Get(e.key); exists {
				colliding = append(colliding, e.key)
			}
		}
		if len(colliding) > 0 && !*overwrite && !*skip {
			return fmt.Errorf("%d key(s) already exist: %s\nuse --overwrite to replace them, or --skip-existing to keep the vault's versions",
				len(colliding), strings.Join(colliding, ", "))
		}

		for _, e := range entries {
			if _, exists := v.Get(e.key); exists && *skip {
				continue
			}
			if err := v.Set(e.key, e.value); err != nil {
				return fmt.Errorf("line %d: %w", e.line, err)
			}
		}
		return nil
	})
}
