package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"kleidos/internal/errs"
	"kleidos/internal/vault"
)

const runUsage = `usage: kleidos run --only K1,K2 [--optional K3] -- command [args...]

Runs a command with the named secrets in its environment.

Values land in the child's environ, which is mode 0400 and owner-only, rather
than in argv, which is 0444 and world-readable via /proc/<pid>/cmdline. That
asymmetry is the entire point of this verb.

At least one of --only and --optional is required. Children inherit the whole
environment, and so do grandchildren, so both name their keys explicitly and
there is deliberately no way to inject the whole vault.

  --only      required keys. A missing one fails before exec, naming every
              absent key, so the command never starts half-configured.
  --optional  keys to inject only if they are present. Absence is not an error;
              this is for a key whose absence is a legitimate state, such as one
              this very command writes on its first run. It does not weaken
              --only, because the caller declares up front what it can survive
              without. A key that is present but empty still fails: empty is a
              vault written wrong, not a key that is absent.

What this guarantees, precisely: kleidos never writes the value to its own stdout
and never places it in argv, and it fails before exec if decryption fails, so the
command never runs with a blank credential. After exec it has no control over
anything. A child that prints its environment leaks, and

    kleidos run --only K -- sh -c 'echo $K'

is a deliberate read, equivalent in intent to reveal. No check here prevents
that, and a name-based check on shell interpreters would break legitimate use
while being defeated by env, make, or any other wrapper.`

// execve is indirected so tests can observe what would have been exec'd.
var execve = syscall.Exec

func Run(args []string) error {
	// -- is required, and is not treated as a mere flag terminator: everything
	// after it belongs to the child, including its own flags.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return fmt.Errorf("run requires -- before the command\n%s", runUsage)
	}
	flagArgs, argv := args[:sep], args[sep+1:]
	if len(argv) == 0 {
		return fmt.Errorf("no command given after --\n%s", runUsage)
	}

	fset := flag.NewFlagSet("run", flag.ContinueOnError)
	fset.SetOutput(os.Stderr)
	fset.Usage = func() { fmt.Fprintln(os.Stderr, runUsage) }
	only := fset.String("only", "", "comma-separated list of keys to inject")
	optional := fset.String("optional", "", "comma-separated list of keys to inject only if present")
	if err := fset.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelp
		}
		return err
	}
	if fset.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q before --\n%s", fset.Arg(0), runUsage)
	}
	if *only == "" && *optional == "" {
		return fmt.Errorf("run requires --only KEY[,KEY...] or --optional KEY[,KEY...]\n%s", runUsage)
	}

	required, err := keyList("--only", *only)
	if err != nil {
		return err
	}
	opt, err := keyList("--optional", *optional)
	if err != nil {
		return err
	}
	// A key in both lists has no coherent reading: it cannot be both required
	// and survivable.
	named := make(map[string]bool, len(required))
	for _, k := range required {
		named[k] = true
	}
	var both []string
	for _, k := range opt {
		if named[k] {
			both = append(both, k)
		}
	}
	if len(both) > 0 {
		return fmt.Errorf("%s named in both --only and --optional", strings.Join(both, ", "))
	}

	// Resolve everything before exec, so a missing key or a failed decryption
	// stops here rather than starting the command with a blank credential.
	keys, secrets, err := lookupSome(required, opt)
	if err != nil {
		return err
	}

	env, err := childEnv(keys, secrets)
	if err != nil {
		return err
	}

	path, err := exec.LookPath(argv[0])
	if err != nil {
		// The shell conventions: 127 for not found, 126 for found but not
		// executable. Both stay out of the 120-125 range, so a caller can still
		// tell our failures from the child's.
		if errors.Is(err, fs.ErrPermission) {
			return errs.Codef(errs.NotExecutable, "%s: not executable", argv[0])
		}
		return errs.Codef(errs.NotFound, "%s: command not found", argv[0])
	}

	// execve rather than fork-and-wait: signal handling and exit-code
	// propagation come out correct for free, and there is no parent left holding
	// plaintext.
	if err := execve(path, argv, env); err != nil {
		switch {
		case errors.Is(err, syscall.EACCES):
			return errs.Codef(errs.NotExecutable, "%s: %v", path, err)
		case errors.Is(err, syscall.ENOENT):
			return errs.Codef(errs.NotFound, "%s: %v", path, err)
		}
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return nil // unreachable on success
}

// keyList splits a comma-separated flag value and validates every name.
func keyList(flag, csv string) ([]string, error) {
	if csv == "" {
		return nil, nil
	}
	keys := strings.Split(csv, ",")
	for _, k := range keys {
		if k == "" {
			return nil, fmt.Errorf("%s contains an empty key name: %q", flag, csv)
		}
		if err := vault.CheckKey(k); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// childEnv builds the child's environment: everything inherited, with the
// resolved secrets overlaid. Secrets win on a collision, but the shadowing is
// reported.
func childEnv(keys []string, secrets []*vault.Secret) ([]string, error) {
	env := os.Environ()
	at := make(map[string]int, len(env))
	for i, kv := range env {
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			at[kv[:eq]] = i
		}
	}

	// Values are re-checked here as a backstop against a vault written by
	// something else: a foreign tool, or a kleidos that predates the non-empty
	// rule. environ entries are NUL-terminated C strings, so a NUL would truncate
	// silently or fail with an opaque EINVAL; an empty value is the present-but-
	// unusable state the write paths exist to prevent, and injecting one is what
	// sends a self-re-execing consumer into a loop.
	//
	// Every offending key is named at once, for the same reason a missing key is:
	// an older vault can hold several, and fixing them one run at a time is a
	// sequence of avoidable failures.
	var bad []string
	var reason error
	for i, k := range keys {
		err := vault.CheckValue(secrets[i].Value)
		if err == nil {
			continue
		}
		// One reason for the whole message. A vault holding both an empty value
		// and a NUL was not written by kleidos at all, and the fix is the same.
		if reason == nil {
			reason = err
		}
		bad = append(bad, k)
	}
	if reason != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(bad, ", "), reason)
	}

	for i, k := range keys {
		entry := k + "=" + secrets[i].Value
		if j, ok := at[k]; ok {
			fmt.Fprintf(os.Stderr, "kleidos: %s was already set in the environment; the vault value wins\n", k)
			env[j] = entry
		} else {
			env = append(env, entry)
		}
	}
	return env, nil
}
