package cmd

import (
	"flag"
	"fmt"
)

const revealUsage = `usage: kleidos reveal [-0] KEY [KEY...]

The explicit plaintext dump. Unlike "get" there is no terminal check: the gate is
the permission rule on this verb, which is the only place it can live.

  -0   emit NUL-delimited values in request order. This is the machine-readable
       path -- K=$(kleidos reveal FOO) silently discards trailing newlines, and
       key and certificate material is exactly the category that has them.`

func Reveal(args []string) error {
	var nul *bool
	keys, err := parseFlags("reveal", revealUsage, args, func(f *flag.FlagSet) {
		nul = f.Bool("0", false, "NUL-delimited output in request order")
	})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("reveal needs at least one key\n%s", revealUsage)
	}

	secrets, err := lookup(keys)
	if err != nil {
		return err
	}
	if *nul {
		return emitNUL(stdout, secrets)
	}
	return emit(stdout, keys, secrets)
}
