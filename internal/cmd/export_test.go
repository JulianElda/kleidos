package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"kleidos/internal/vault"
)

// TestExportEvalsBackToTheSameBytes is the end-to-end claim: whatever went into
// the vault comes back out of a real shell unchanged.
func TestExportEvalsBackToTheSameBytes(t *testing.T) {
	found := shells(t)

	dir := vaultDir(t)
	want := map[string]string{}
	for i, c := range corpus {
		key := fmt.Sprintf("K%02d", i)
		if err := setStdin(t, key, c.value); err != nil {
			t.Fatalf("seeding %s: %v", c.name, err)
		}
		want[key] = c.value
	}
	_ = dir

	out := capture(t)
	if err := Export(nil); err != nil {
		t.Fatal(err)
	}
	exports := out.String()

	for shellName, shellPath := range found {
		t.Run(shellName, func(t *testing.T) {
			work := t.TempDir()
			if err := os.WriteFile(filepath.Join(work, "exports.sh"), []byte(exports), 0600); err != nil {
				t.Fatal(err)
			}

			keys := make([]string, 0, len(want))
			for k := range want {
				keys = append(keys, k)
			}

			var script strings.Builder
			script.WriteString("eval \"$(cat exports.sh)\"\n")
			for _, k := range keys {
				fmt.Fprintf(&script, "printf '%%s\\0' \"$%s\"\n", k)
			}

			sh := exec.Command(shellPath, "-c", script.String())
			sh.Dir = work
			got, err := sh.Output()
			if err != nil {
				t.Fatalf("%s: %v", shellPath, err)
			}

			parts := strings.Split(string(got), "\x00")
			if len(parts) != len(keys)+1 {
				t.Fatalf("got %d fields, want %d", len(parts)-1, len(keys))
			}
			for i, k := range keys {
				if parts[i] != want[k] {
					t.Errorf("%s: got %q, want %q", k, parts[i], want[k])
				}
			}
		})
	}
}

// Nothing but export lines: no double quotes, no printf %q, no commentary.
func TestExportEmitsOnlyExportLines(t *testing.T) {
	vaultDir(t)
	for _, pair := range [][2]string{{"A", "1"}, {"B", "with 'quote' and $(id)"}} {
		if err := setStdin(t, pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	out := capture(t)
	if err := Export(nil); err != nil {
		t.Fatal(err)
	}

	line := regexp.MustCompile(`^export [A-Z_][A-Z0-9_]*='(?s).*'$`)
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	// A value containing a newline spans lines, so join and check the whole form
	// rather than each physical line.
	joined := strings.Join(lines, "\n")
	for _, stmt := range regexp.MustCompile(`(?m)^export `).Split(joined, -1)[1:] {
		if !line.MatchString("export " + strings.TrimSuffix(stmt, "\n")) {
			t.Errorf("unexpected output shape: %q", stmt)
		}
	}
	if strings.Contains(joined, `="`) {
		t.Errorf("values must be single-quoted: %q", joined)
	}
}

// A key name that violates the constraint fails the whole export, rather than
// being skipped. A silently short export is how a caller ends up running with a
// missing credential -- and the left-hand side of an eval'ed assignment is its
// own injection point.
func TestExportRefusesBadKeyNameWholesale(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "GOOD", "1"); err != nil {
		t.Fatal(err)
	}

	// Bypass Set to plant a name no write path would have accepted, standing in
	// for a vault written by an older or buggier build.
	s, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(v *vault.Vault) error {
		v.Secrets["evil; rm -rf /"] = &vault.Secret{Value: "x"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	out := capture(t)
	err = Export(nil)
	if err == nil {
		t.Fatal("export accepted an invalid key name")
	}
	if !strings.Contains(err.Error(), "refusing to export") {
		t.Fatalf("error should say the export was refused, got: %v", err)
	}
	if strings.Contains(out.String(), "GOOD") {
		t.Fatalf("a refused export still emitted assignments: %q", out.String())
	}
}

func TestExportRejectsArguments(t *testing.T) {
	vaultDir(t)
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	capture(t)
	if err := Export([]string{"A"}); err == nil {
		t.Fatal("export took a positional argument")
	}
}
