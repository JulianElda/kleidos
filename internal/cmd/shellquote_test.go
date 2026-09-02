package cmd

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kleidos/internal/errs"
)

// corpus is the set of values that break naive quoting. Every entry is here
// because some plausible implementation mangles it.
var corpus = []struct{ name, value string }{
	{"empty", ""},
	{"plain", "hunter2"},
	{"bare single quote", `'`},
	{"the escape sequence as data", `'\''`},
	{"double quote", `"`},
	{"command substitution", `$(id)`},
	{"backtick substitution", "`id`"},
	{"parameter expansion", `${HOME}`},
	{"lone backslash", `\`},
	{"literal backslash n", `\n`},
	{"embedded newline", "a\nb"},
	{"trailing newlines", "body\n\n\n"},
	{"leading and trailing space", "  padded  "},
	{"tab", "a\tb"},
	{"history expansion", `!`},
	{"comment", `#comment`},
	{"flag lookalike", `--not-a-flag`},
	{"quote soup", `'"'"'$\`},
	{"utf8", "clé—κλειδός"},
	{"random printable", randomPrintable(1000, 1)},
}

func randomPrintable(n int, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0x20 + r.Intn(0x7f-0x20))
	}
	return string(b)
}

// unquote reverses shellQuote, following the same rules a POSIX shell does. It
// exists so the fuzz target can check the round trip without spawning a shell.
func unquote(q string) (string, error) {
	if len(q) < 2 || q[0] != '\'' || q[len(q)-1] != '\'' {
		return "", fmt.Errorf("not single-quoted: %q", q)
	}
	var sb strings.Builder
	for i := 1; i < len(q)-1; {
		if q[i] != '\'' {
			sb.WriteByte(q[i])
			i++
			continue
		}
		// The only legal appearance of a quote inside the body is the four-byte
		// sequence '\'' -- here we sit on its first byte.
		if !strings.HasPrefix(q[i:], `'\''`) {
			return "", fmt.Errorf("bare quote at %d in %q", i, q)
		}
		sb.WriteByte('\'')
		i += 4
	}
	return sb.String(), nil
}

func TestShellQuoteRejectsNUL(t *testing.T) {
	_, err := shellQuote([]byte("a\x00b"))
	if !errors.Is(err, errs.ErrNUL) {
		t.Fatalf("want ErrNUL, got %v", err)
	}
}

func TestShellQuoteStructure(t *testing.T) {
	for _, c := range corpus {
		got, err := shellQuote([]byte(c.value))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		back, err := unquote(got)
		if err != nil {
			t.Fatalf("%s: %v (quoted: %q)", c.name, err, got)
		}
		if back != c.value {
			t.Fatalf("%s: round trip gave %q, want %q", c.name, back, c.value)
		}
	}
}

// FuzzShellQuote checks the structural invariant at volume, without spawning a
// shell: the output is single-quoted, contains no bare quote, and unquotes back
// to the input byte for byte. TestShellQuoteThroughRealShells provides the
// fidelity that this cannot.
func FuzzShellQuote(f *testing.F) {
	for _, c := range corpus {
		f.Add(c.value)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got, err := shellQuote([]byte(v))
		if strings.IndexByte(v, 0) >= 0 {
			if !errors.Is(err, errs.ErrNUL) {
				t.Fatalf("NUL input must be rejected, got %q, %v", got, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", v, err)
		}
		back, err := unquote(got)
		if err != nil {
			t.Fatalf("%q quoted to %q: %v", v, got, err)
		}
		if back != v {
			t.Fatalf("round trip: %q -> %q -> %q", v, got, back)
		}
	})
}

// shells resolves dash and bash, and refuses to run if they turn out to be the
// same binary.
//
// /bin/sh is bash on this machine, so a suite that ran `sh` and then `bash`
// would test bash twice and report a false pass on the one function where being
// wrong is code execution.
func shells(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	for _, name := range []string{"dash", "bash"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s is not installed; refusing to claim two-shell coverage without it", name)
		}
		found[name] = path
	}

	a, err := os.Stat(found["dash"])
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(found["bash"])
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(a, b) {
		t.Fatalf("dash (%s) and bash (%s) are the same binary; two-shell coverage would be a false pass",
			found["dash"], found["bash"])
	}
	return found
}

// substitution modes that kleidos supports.
//
// Two plausible modes are deliberately absent, both for reasons that belong to
// the shell rather than to the quoting:
//
//   - Unquoted `eval $(kleidos export)` word-splits the output, collapsing
//     newlines inside values into spaces.
//   - `s=$(kleidos export); eval "$s"` corrupts some high bytes under dash. See
//     TestDashCorruptsHighBytesThroughCommandSubstitution, which reproduces it
//     with no quoting involved at all.
var evalModes = []struct{ name, script string }{
	{"quoted command substitution", `eval "$(cat exports.sh)"`},
	{"quoted backticks", "eval \"`cat exports.sh`\""},
	{"source the file", `. ./exports.sh`},
}

// TestDashCorruptsHighBytesThroughCommandSubstitution records a dash behaviour
// that kleidos cannot fix and must not be blamed for.
//
// Assigning a command substitution to a variable in dash injects 0x81 (its
// internal CTLESC marker) before certain high bytes. There is no eval here and
// no quoting: it is command substitution into a variable, and it corrupts the
// value on its own.
//
// The consequence for callers is the same conclusion the handoff reaches for
// trailing newlines by a different route: K=$(kleidos reveal FOO) is lossy, and
// `reveal -0` is the machine-readable path.
func TestDashCorruptsHighBytesThroughCommandSubstitution(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash is not installed")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}

	// 0xc2 0x82 is U+0082; the trailing byte is the one dash escapes.
	const script = `s=$(printf "aÂb"); printf %s "$s"`
	want := "aÂb"

	out, err := exec.Command(bash, "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != want {
		t.Fatalf("bash is expected to be byte-exact here; got % x, want % x", out, want)
	}

	out, err = exec.Command(dash, "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) == want {
		t.Skip("dash no longer corrupts high bytes through command substitution; " +
			"the intermediate-variable mode could be restored to evalModes")
	}
	if string(out) != "aÂb" {
		t.Logf("dash corrupts this differently than recorded: got % x", out)
	}
	t.Logf("dash (%s) injects CTLESC: got % x, want % x -- a dash bug, not a quoting bug", dash, out, want)
}

// TestShellQuoteThroughRealShells runs the whole corpus through both shells in
// each supported substitution mode, comparing bytes.
func TestShellQuoteThroughRealShells(t *testing.T) {
	found := shells(t)

	keys := make([]string, len(corpus))
	var exports strings.Builder
	for i, c := range corpus {
		keys[i] = fmt.Sprintf("K%02d", i)
		quoted, err := shellQuote([]byte(c.value))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fmt.Fprintf(&exports, "export %s=%s\n", keys[i], quoted)
	}

	for shellName, shellPath := range found {
		for _, mode := range evalModes {
			t.Run(shellName+"/"+mode.name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "exports.sh"), []byte(exports.String()), 0600); err != nil {
					t.Fatal(err)
				}

				// Print every value NUL-delimited, so trailing whitespace and
				// newlines are compared rather than eaten.
				var script strings.Builder
				script.WriteString(mode.script + "\n")
				for _, k := range keys {
					fmt.Fprintf(&script, "printf '%%s\\0' \"$%s\"\n", k)
				}

				sh := exec.Command(shellPath, "-c", script.String())
				sh.Dir = dir // the script reads exports.sh relatively
				out, err := sh.Output()
				if err != nil {
					t.Fatalf("%s: %v", shellPath, err)
				}

				parts := strings.Split(string(out), "\x00")
				if len(parts) != len(corpus)+1 {
					t.Fatalf("got %d fields, want %d", len(parts)-1, len(corpus))
				}
				for i, c := range corpus {
					if parts[i] != c.value {
						t.Errorf("%s: got %q, want %q", c.name, parts[i], c.value)
					}
				}
			})
		}
	}
}

// shellBreakers are the bytes most likely to escape quoting, oversampled by the
// random test.
var shellBreakers = []byte("'\"$\\`\n\t !#{}()")

// TestShellQuoteRandomThroughRealShells pushes volume through the real shells,
// batched into one invocation per shell so that thousands of values cost two
// processes rather than thousands.
func TestShellQuoteRandomThroughRealShells(t *testing.T) {
	found := shells(t)

	const n = 2000
	r := rand.New(rand.NewSource(20260902))

	values := make([]string, n)
	keys := make([]string, n)
	var exports strings.Builder
	for i := range values {
		// Draw from the bytes that actually break shells, plus arbitrary ones.
		b := make([]byte, r.Intn(40))
		for j := range b {
			if r.Intn(3) == 0 {
				b[j] = shellBreakers[r.Intn(len(shellBreakers))]
			} else {
				b[j] = byte(1 + r.Intn(0xff)) // never 0: NUL is rejected upstream
			}
		}
		values[i] = string(b)
		keys[i] = fmt.Sprintf("K%04d", i)
		quoted, err := shellQuote(b)
		if err != nil {
			t.Fatalf("value %d: %v", i, err)
		}
		fmt.Fprintf(&exports, "export %s=%s\n", keys[i], quoted)
	}

	for shellName, shellPath := range found {
		t.Run(shellName, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "exports.sh")
			if err := os.WriteFile(path, []byte(exports.String()), 0600); err != nil {
				t.Fatal(err)
			}

			var script strings.Builder
			fmt.Fprintf(&script, "eval \"$(cat %s)\"\n", path)
			for _, k := range keys {
				fmt.Fprintf(&script, "printf '%%s\\0' \"$%s\"\n", k)
			}

			out, err := exec.Command(shellPath, "-c", script.String()).Output()
			if err != nil {
				t.Fatalf("%s: %v", shellPath, err)
			}
			parts := strings.Split(string(out), "\x00")
			if len(parts) != n+1 {
				t.Fatalf("got %d fields, want %d", len(parts)-1, n)
			}
			for i, want := range values {
				if parts[i] != want {
					t.Errorf("value %d: got %q, want %q", i, parts[i], want)
				}
			}
		})
	}
}
