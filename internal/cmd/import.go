package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"kleidos/internal/vault"
)

const importUsage = `usage: kleidos import FILE [--null]
       kleidos import --stdin [--null]

Loads assignments from a file or from standard input.

The default format is a strict subset of .env. Anything outside that subset is an
error naming the line and the key, because a silently mis-parsed value stored as
a secret is discovered at the worst possible moment. No expansion is performed in
either quote style: a .env file is data, not a script.

  --stdin    read from standard input instead of a file
  --null     read NUL-delimited KEY=value records instead of .env

--null is the format for generated input. It has no quoting rules to satisfy and
no ambiguity to resolve: NUL is the one byte no stored value may contain, so it
delimits records without escaping, and everything after the first = is the value
verbatim. Use it whenever the producer is a program rather than a person --
especially for values it cannot regenerate, where a refused import is how
plaintext ends up somewhere it was not meant to go.

If any key in the input already exists in the vault, nothing is imported and
every collision is listed. Either flag below is applied to the whole input or not
at all -- a half-applied import leaves the vault in a state nobody chose.

  --overwrite       replace the vault's version of every colliding key
  --skip-existing   keep the vault's version of every colliding key`

func Import(args []string) error {
	var overwrite, skip, stdin, null *bool
	rest, err := parseFlags("import", importUsage, args, func(f *flag.FlagSet) {
		overwrite = f.Bool("overwrite", false, "replace colliding keys")
		skip = f.Bool("skip-existing", false, "keep the vault's version of colliding keys")
		stdin = f.Bool("stdin", false, "read from standard input")
		null = f.Bool("null", false, "read NUL-delimited KEY=value records")
	})
	if err != nil {
		return err
	}
	if *overwrite && *skip {
		return fmt.Errorf("--overwrite and --skip-existing are mutually exclusive")
	}

	// The source is either a named file or stdin, never both: `import --stdin
	// FILE` has two readings and neither is worth guessing at.
	var src io.Reader
	var name string
	if *stdin {
		if len(rest) != 0 {
			return fmt.Errorf("import --stdin takes no file\n%s", importUsage)
		}
		src, name = os.Stdin, "stdin"
	} else {
		if len(rest) != 1 {
			return fmt.Errorf("import takes exactly one file, or --stdin\n%s", importUsage)
		}
		f, err := os.Open(rest[0])
		if err != nil {
			return fmt.Errorf("opening %s: %w", rest[0], err)
		}
		defer f.Close()
		src, name = f, rest[0]
	}

	parse := parseDotenv
	if *null {
		parse = parseNullRecords
	}
	entries, err := parse(src)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s: no assignments found", name)
	}
	// The same write-time invariants as `set`, checked here rather than
	// downstream so that every consumer can rely on values being non-empty and
	// NUL-free -- and checked before the store is opened, so a bad input never
	// creates a vault. The key is named as well as the location: for generated
	// input the key is the stable identifier and the location is noise.
	for _, e := range entries {
		if err := vault.CheckValue(e.value); err != nil {
			return fmt.Errorf("%s: %s (%s): %w", name, e.loc, e.key, err)
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
				return fmt.Errorf("%s (%s): %w", e.loc, e.key, err)
			}
		}
		return nil
	})
}
