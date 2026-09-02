// Command kleidos manages key/value secrets in a single age-encrypted file.
//
// It offers no boundary against a process running as the user: the identity has
// no passphrase, by choice, because that is what makes unattended operation
// work. What it buys is that secrets are not in plaintext on disk, not in argv,
// and not in an agent transcript by default. Rotation is the recovery path.
package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"kleidos/internal/cmd"
	"kleidos/internal/errs"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `kleidos -- key/value secrets in a single age-encrypted file

usage:
  kleidos set KEY [--stdin]        store a value (prompts on the terminal)
  kleidos get KEY [KEY...]         print values; terminal only
  kleidos reveal [-0] KEY [KEY...] print values unconditionally
  kleidos list                     names, timestamps, fingerprints
  kleidos delete KEY               remove a key
  kleidos rename OLD NEW [--force] rename, preserving the update time
  kleidos run --only K1,K2 -- cmd  exec cmd with the named secrets in its env
  kleidos export                   emit shell assignments for eval
  kleidos import FILE              load a strict subset of .env

Values are never taken as arguments: argv is world-readable via /proc.
`

func main() {
	// Refuse to dump core. One syscall, and it buys more than zeroing does: a
	// core file would contain every plaintext the process ever held, on disk,
	// outside the age envelope. Best-effort -- if it fails there is nothing
	// useful to say about it.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})

	os.Exit(dispatch(os.Args[1:]))
}

func dispatch(args []string) int {
	if len(args) == 0 {
		io.WriteString(os.Stderr, usage)
		return errs.Generic
	}

	verb, rest := args[0], args[1:]

	var err error
	switch verb {
	case "set":
		err = cmd.Set(rest)
	case "get":
		err = cmd.Get(rest)
	case "reveal":
		err = cmd.Reveal(rest)
	case "list":
		err = cmd.List(rest)
	case "delete":
		err = cmd.Delete(rest)
	case "rename":
		err = cmd.Rename(rest)
	case "run":
		// On success this execs and does not return.
		err = cmd.Run(rest)
	case "export":
		err = cmd.Export(rest)
	case "import":
		err = cmd.Import(rest)
	case "help", "-h", "--help":
		io.WriteString(os.Stdout, usage)
		return errs.OK
	case "version", "--version":
		fmt.Println("kleidos", version)
		return errs.OK
	default:
		fmt.Fprintf(os.Stderr, "kleidos: unknown command %q\n\n", verb)
		io.WriteString(os.Stderr, usage)
		return errs.Generic
	}

	if err != nil {
		// A verb's own -h already printed its usage.
		if cmd.IsHelp(err) {
			return errs.OK
		}
		fmt.Fprintln(os.Stderr, "kleidos:", err)
		return errs.Code(err)
	}
	return errs.OK
}
