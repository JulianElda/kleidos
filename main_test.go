package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"kleidos/internal/errs"
	"kleidos/internal/testenv"
)

// These tests drive the built binary instead of calling into internal/*.
//
// Everything below the CLI is already covered, and covered better than a
// subprocess could manage: real dash and bash in export_test.go and
// shellquote_test.go, the write-path stress in vault, the fuzz target. What
// has nothing is the process itself, and three of the invariants in
// CLAUDE.md are only true at that level:
//
//   - Exit codes. errs.Code is checked in five unit tests; none of them
//     observes a wait status, so "anything below 120 came from a run child"
//     was a claim about a function.
//   - run's execve. Every test in cmd stubs it, so "the value lands in the
//     child's environ, never in its argv" was asserted about a []string.
//     Here a real child reads its own /proc entries.
//   - get's terminal gate. isTerminal is a seam; the real check lived in
//     docs/verifying.md as a manual one-liner. It is a test now.
//
// Nothing here re-tests what the unit suites own. If a case can be written
// against a function, it belongs there instead.

const (
	testKey   = "E2E_SECRET"
	testValue = "hunter2-e2e-a1b2c3"
)

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
)

// binary builds the CLI once per run. Building rather than calling dispatch
// in-process is the whole point: main.go is the code under test, so a verb
// missing from the switch, or an error whose status never reaches os.Exit,
// has to be able to fail here.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		var dir string
		if dir, buildErr = os.MkdirTemp("", "kleidos-e2e-*"); buildErr != nil {
			return
		}
		builtBin = filepath.Join(dir, "kleidos")
		if out, err := exec.Command("go", "build", "-o", builtBin, ".").CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtBin
}

func TestMain(m *testing.M) {
	code := m.Run()
	if builtBin != "" {
		_ = os.RemoveAll(filepath.Dir(builtBin))
	}
	os.Exit(code)
}

// cli is the built binary pointed at a scratch vault.
type cli struct {
	t   *testing.T
	bin string
	dir string
}

// newCLI returns a CLI whose vault directory holds an identity and its
// recipients, but no secrets file yet.
func newCLI(t *testing.T) *cli {
	t.Helper()
	return &cli{t: t, bin: binary(t), dir: testenv.Vault(t)}
}

// exec runs the binary with stdin as its input, returning stdout, stderr and
// the exit status rather than failing: most of these tests are about the
// status and the message.
//
// KLEIDOS_DIR is appended last so it wins over any the developer has set --
// os/exec keeps the last of a duplicated name. Nothing here may reach the
// real vault.
func (c *cli) exec(stdin string, args ...string) (string, string, int) {
	c.t.Helper()
	cmd := exec.Command(c.bin, args...)
	cmd.Env = append(os.Environ(), "KLEIDOS_DIR="+c.dir)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		c.t.Fatalf("running %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), code
}

// mustExec fails the test if the invocation did not succeed.
func (c *cli) mustExec(stdin string, args ...string) string {
	c.t.Helper()
	stdout, stderr, code := c.exec(stdin, args...)
	if code != errs.OK {
		c.t.Fatalf("kleidos %v exited %d\n%s\n%s", args, code, stdout, stderr)
	}
	return stdout
}

// set stores a value through the real write path.
func (c *cli) set(key, value string) {
	c.t.Helper()
	c.mustExec(value, "set", key, "--stdin")
}

func TestExitStatusReachesTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T) *cli
		args  []string
		want  int
	}{
		{
			// reveal, not get: get refuses on the terminal check before it
			// ever looks a key up, and that ordering is itself deliberate.
			name:  "missing key",
			setup: seeded,
			args:  []string{"reveal", "NO_SUCH_KEY"},
			want:  errs.KeyNotFound,
		},
		{
			name:  "no vault yet",
			setup: newCLI,
			args:  []string{"reveal", testKey},
			want:  errs.VaultNotFound,
		},
		{
			// A vault that exists but cannot be opened. Distinct from the
			// case above on purpose: reading the two alike is how a caller
			// ends up provisioning over secrets it merely failed to read.
			name: "identity gone",
			setup: func(t *testing.T) *cli {
				c := seeded(t)
				if err := os.Remove(filepath.Join(c.dir, "identity")); err != nil {
					t.Fatal(err)
				}
				return c
			},
			args: []string{"reveal", testKey},
			want: errs.Identity,
		},
		{
			// stdout and stderr are both pipes here, which is exactly the
			// captured-invocation shape the gate exists for.
			name:  "get without a terminal",
			setup: seeded,
			args:  []string{"get", testKey},
			want:  errs.NoTerminal,
		},
		{
			name:  "unknown verb",
			setup: seeded,
			args:  []string{"frobnicate"},
			want:  errs.Generic,
		},
		{
			name:  "no arguments",
			setup: seeded,
			args:  nil,
			want:  errs.Generic,
		},
		{
			name:  "absent key",
			setup: seeded,
			args:  []string{"has", "NO_SUCH_KEY"},
			want:  errs.KeyNotFound,
		},
		{
			name:  "present key",
			setup: seeded,
			args:  []string{"has", testKey},
			want:  errs.OK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.setup(t)
			stdout, stderr, code := c.exec("", tc.args...)
			if code != tc.want {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tc.want, stdout, stderr)
			}
		})
	}
}

// seeded is a CLI whose vault already holds testKey.
func seeded(t *testing.T) *cli {
	t.Helper()
	c := newCLI(t)
	c.set(testKey, testValue)
	return c
}

// TestHasPrintsNothingOnStdout is what keeps has plaintext-free, and so
// approval-free: a permission rule can allow it unconditionally only because
// no arrangement of arguments makes it emit a value.
func TestHasPrintsNothingOnStdout(t *testing.T) {
	c := seeded(t)
	for _, args := range [][]string{
		{"has", testKey},
		{"has", "NO_SUCH_KEY"},
		{"has", testKey, "NO_SUCH_KEY"},
	} {
		if stdout, _, _ := c.exec("", args...); stdout != "" {
			t.Errorf("kleidos %v wrote to stdout: %q", args, stdout)
		}
	}
}

func TestRunPropagatesTheChildsExitStatus(t *testing.T) {
	c := seeded(t)
	// Every one of these is below 120, which is the whole reason kleidos's
	// own codes start there: a caller reading 3 must be able to conclude the
	// child said 3, not that kleidos did.
	for _, want := range []int{0, 1, 3, 42, 119} {
		script := fmt.Sprintf("exit %d", want)
		if _, stderr, code := c.exec("", "run", "--only", testKey, "--", "sh", "-c", script); code != want {
			t.Errorf("%q exited %d, want %d\n%s", script, code, want, stderr)
		}
	}
}

func TestRunFollowsTheShellConventionsForABadCommand(t *testing.T) {
	c := seeded(t)

	notExecutable := filepath.Join(c.dir, "not-executable")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, command string
		want          int
	}{
		{"not found", filepath.Join(c.dir, "no-such-command"), errs.NotFound},
		{"not executable", notExecutable, errs.NotExecutable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := c.exec("", "run", "--only", testKey, "--", tc.command)
			if code != tc.want {
				t.Fatalf("exit %d, want %d: %s", code, tc.want, stderr)
			}
		})
	}
}

// TestRunPlacesTheValueInTheChildsEnvironNotItsArgv is the invariant the verb
// exists for, asserted where it is actually true: in a real child's own /proc
// entries, rather than in a captured argument to a stubbed execve.
//
// The mode asymmetry underneath it -- cmdline 0444, environ 0400 -- is a
// kernel property, not kleidos's, and is re-checked by hand; see the first of
// the one-liners in docs/verifying.md.
func TestRunPlacesTheValueInTheChildsEnvironNotItsArgv(t *testing.T) {
	c := seeded(t)

	// $$ inside `sh -c` is the exec'd shell itself, so these are the very
	// process kleidos handed the secret to.
	const script = `cat /proc/$$/cmdline; printf '\n---\n'; cat /proc/$$/environ`
	stdout := c.mustExec("", "run", "--only", testKey, "--", "sh", "-c", script)

	before, after, ok := strings.Cut(stdout, "\n---\n")
	if !ok {
		t.Fatalf("child did not print both /proc entries:\n%q", stdout)
	}
	// Both files are NUL-delimited, so an entry appears as a contiguous run.
	cmdline := strings.ReplaceAll(before, "\x00", " ")
	if !strings.Contains(cmdline, "sh") || !strings.Contains(cmdline, script) {
		t.Fatalf("read the wrong process's cmdline: %q", cmdline)
	}
	if strings.Contains(before, testValue) {
		t.Errorf("the value reached the child's argv: %q", cmdline)
	}
	if !strings.Contains(after, testKey+"="+testValue) {
		t.Errorf("the value did not reach the child's environ")
	}
}

// TestTheChildInheritsTheCoreDumpRefusal covers the one line of main() that
// runs before any verb. rlimits survive execve, so a run child is where both
// halves are observable at once: that main set it, and that it still holds
// for the process actually handling the plaintext.
func TestTheChildInheritsTheCoreDumpRefusal(t *testing.T) {
	c := seeded(t)
	limits := c.mustExec("", "run", "--only", testKey, "--", "sh", "-c", "cat /proc/self/limits")

	const label = "Max core file size"
	for _, line := range strings.Split(limits, "\n") {
		if !strings.HasPrefix(line, label) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, label))
		if len(fields) < 2 || fields[0] != "0" || fields[1] != "0" {
			t.Fatalf("core dumps are not refused: %q", line)
		}
		return
	}
	t.Fatalf("no %q line in:\n%s", label, limits)
}

// TestGetPrintsWhenStderrIsATerminal is the positive half of the gate, and it
// is the arrangement the gate was designed around: stderr on a terminal,
// stdout redirected. `kleidos get K > file` has to keep working for a human
// while the fully-captured case in TestExitStatusReachesTheProcess refuses.
func TestGetPrintsWhenStderrIsATerminal(t *testing.T) {
	c := seeded(t)
	master, slave := openPTY(t)

	cmd := exec.Command(c.bin, "get", testKey)
	cmd.Env = append(os.Environ(), "KLEIDOS_DIR="+c.dir)
	var stdout strings.Builder
	cmd.Stdout = &stdout // a pipe, deliberately: only stderr is the terminal
	cmd.Stderr = slave

	// Nothing is expected on the terminal, but an unread master would block
	// the child if anything were written to it.
	go func() { _, _ = io.Copy(io.Discard, master) }()

	if err := cmd.Run(); err != nil {
		t.Fatalf("get with a terminal on stderr failed: %v", err)
	}
	if got, want := stdout.String(), testValue+"\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

// openPTY allocates a pseudo-terminal and returns its two ends.
//
// Done here rather than through script(1) because the property under test is
// that the two descriptors are treated differently, and script puts all three
// on the same terminal. It is also one less thing the suite has to require of
// the machine.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	var unlock int32 // 0 unlocks the slave side
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); err != nil {
		t.Fatalf("unlocking pty: %v", err)
	}
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		t.Fatalf("naming pty: %v", err)
	}

	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("opening pty slave: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return m, s
}

func ioctl(fd, request, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, arg); errno != 0 {
		return errno
	}
	return nil
}

// verbLine matches a usage entry: two spaces, the program name, the verb.
var verbLine = regexp.MustCompile(`(?m)^  kleidos ([a-z]+)`)

// documentedVerbs is what `kleidos help` claims the program can do.
func documentedVerbs(t *testing.T, c *cli) []string {
	t.Helper()
	matches := verbLine.FindAllStringSubmatch(c.mustExec("", "help"), -1)
	if len(matches) == 0 {
		t.Fatal("no verbs found in the usage text")
	}
	var verbs []string
	for _, m := range matches {
		verbs = append(verbs, m[1])
	}
	return verbs
}

// banner is the first line of main's own usage text. Seeing it back from a
// verb means dispatch never reached one.
const banner = "kleidos -- key/value secrets"

// TestEveryDocumentedVerbIsRegistered catches step 6 of "Adding a verb" going
// half-done: a verb written up in the usage text but never added to the
// dispatch switch answers "unknown command", and no test below main can see
// it. Each verb's own -h is the probe, since it reaches the verb without
// touching the vault.
//
// The evidence is the verb printing its own usage, not the exit status: run
// hand-rolls its parsing because -- separates the child's argv, so `run -h`
// reports the missing -- before it ever looks at flags. That is deliberate,
// and it still proves dispatch arrived.
func TestEveryDocumentedVerbIsRegistered(t *testing.T) {
	c := newCLI(t)
	for _, verb := range documentedVerbs(t, c) {
		stdout, stderr, _ := c.exec("", verb, "-h")
		out := stdout + stderr
		switch {
		case strings.Contains(out, "unknown command"):
			t.Errorf("%s is documented but not registered", verb)
		case strings.Contains(out, banner):
			t.Errorf("kleidos %s -h fell back to the general usage", verb)
		case !strings.Contains(out, "usage:"):
			t.Errorf("kleidos %s -h printed no usage of its own:\n%s", verb, out)
		}
	}
}

// TestEveryVerbHasAPermissionRule is step 7. A verb that reaches the README's
// usage list without reaching its permission snippet is one an agent harness
// will prompt on every time, or -- worse, if it prints plaintext and someone
// adds a blanket allow later -- will not prompt on at all.
func TestEveryVerbHasAPermissionRule(t *testing.T) {
	c := newCLI(t)
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range documentedVerbs(t, c) {
		rule := fmt.Sprintf("%q", "Bash(kleidos "+verb+":*)")
		if !strings.Contains(string(readme), rule) {
			t.Errorf("no permission rule for %s; expected %s in the README snippet", verb, rule)
		}
	}
}
