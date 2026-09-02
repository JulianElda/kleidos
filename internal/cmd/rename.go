package cmd

import (
	"flag"
	"fmt"

	"kleidos/internal/errs"
	"kleidos/internal/vault"
)

const renameUsage = `usage: kleidos rename OLD NEW [--force]

Renames a secret, preserving its update time -- the value did not change, only
its name.

Refuses when NEW already exists, because silently clobbering a live credential is
unrecoverable once secrets.age.bak rolls over. --force overwrites.`

func Rename(args []string) error {
	var force *bool
	rest, err := parseFlags("rename", renameUsage, args, func(f *flag.FlagSet) {
		force = f.Bool("force", false, "overwrite NEW if it already exists")
	})
	if err != nil {
		return err
	}
	if len(rest) != 2 {
		return fmt.Errorf("rename takes exactly two keys\n%s", renameUsage)
	}
	old, name := rest[0], rest[1]
	if old == name {
		return fmt.Errorf("OLD and NEW are the same key: %s", old)
	}
	if err := vault.CheckKey(name); err != nil {
		return err
	}

	s, err := openStore()
	if err != nil {
		return err
	}
	return s.Update(func(v *vault.Vault) error {
		if _, ok := v.Get(old); !ok {
			return fmt.Errorf("%w: %s", errs.ErrKeyNotFound, old)
		}
		if _, exists := v.Get(name); exists && !*force {
			return fmt.Errorf("refusing to overwrite existing key %s; pass --force to clobber it", name)
		}
		return v.Rename(old, name)
	})
}
