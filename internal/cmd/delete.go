package cmd

import (
	"fmt"

	"kleidos/internal/errs"
	"kleidos/internal/vault"
)

const deleteUsage = `usage: kleidos delete KEY

Removes KEY. Like every mutation this is a read-modify-write of the whole blob:
the previous ciphertext remains as secrets.age.bak until the next write.`

func Delete(args []string) error {
	rest, err := parseFlags("delete", deleteUsage, args, nil)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("delete takes exactly one key\n%s", deleteUsage)
	}
	key := rest[0]

	s, err := openStore()
	if err != nil {
		return err
	}
	return s.Update(func(v *vault.Vault) error {
		if !v.Delete(key) {
			return fmt.Errorf("%w: %s", errs.ErrKeyNotFound, key)
		}
		return nil
	})
}
