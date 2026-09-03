package cmd

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"kleidos/internal/errs"
)

// capture redirects the verbs' stdout and returns what was written.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = old })
	return &buf
}

// asTerminal makes the stderr terminal check pass, standing in for a human at a
// real terminal.
func asTerminal(t *testing.T, yes bool) {
	t.Helper()
	old := isTerminal
	isTerminal = func(*os.File) bool { return yes }
	t.Cleanup(func() { isTerminal = old })
}

func seed(t *testing.T, pairs ...string) string {
	t.Helper()
	dir := vaultDir(t)
	for i := 0; i < len(pairs); i += 2 {
		if err := setStdin(t, pairs[i], pairs[i+1]); err != nil {
			t.Fatalf("seeding %s: %v", pairs[i], err)
		}
	}
	return dir
}

func TestGetRefusesWithoutTerminalOnStderr(t *testing.T) {
	seed(t, "DB_USER", "alice")
	asTerminal(t, false)
	out := capture(t)

	err := Get([]string{"DB_USER"})
	if !errors.Is(err, errs.ErrNoTerminal) {
		t.Fatalf("want ErrNoTerminal, got %v", err)
	}
	if errs.Code(err) != errs.NoTerminal {
		t.Fatalf("want exit %d, got %d", errs.NoTerminal, errs.Code(err))
	}
	if out.Len() != 0 {
		t.Fatalf("refused get still wrote %q", out.String())
	}
}

func TestGetSingleKeyPrintsValue(t *testing.T) {
	seed(t, "DB_USER", "alice")
	asTerminal(t, true)
	out := capture(t)

	if err := Get([]string{"DB_USER"}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "alice\n" {
		t.Fatalf("got %q, want %q", got, "alice\n")
	}
}

func TestGetMultipleKeysAreLabelled(t *testing.T) {
	seed(t, "DB_USER", "alice", "DB_PASSWORD", "hunter2")
	asTerminal(t, true)
	out := capture(t)

	if err := Get([]string{"DB_PASSWORD", "DB_USER"}); err != nil {
		t.Fatal(err)
	}
	// Request order, not vault order.
	want := "DB_PASSWORD=hunter2\nDB_USER=alice\n"
	if got := out.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGetIsAllOrNothing(t *testing.T) {
	seed(t, "PRESENT", "x")
	asTerminal(t, true)
	out := capture(t)

	err := Get([]string{"MISSING_A", "PRESENT", "MISSING_B"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	// Every missing name is reported, not just the first.
	for _, name := range []string{"MISSING_A", "MISSING_B"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should name %s, got: %v", name, err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("partial read leaked %q", out.String())
	}
}

func TestGetOnAbsentVault(t *testing.T) {
	vaultDir(t)
	asTerminal(t, true)
	err := Get([]string{"ANY"})
	if !errors.Is(err, errs.ErrVaultNotFound) {
		t.Fatalf("want ErrVaultNotFound, got %v", err)
	}
	if errs.Code(err) != errs.VaultNotFound {
		t.Fatalf("want exit %d, got %d", errs.VaultNotFound, errs.Code(err))
	}
}

// reveal is the deliberate dump: it has no terminal check at all.
func TestRevealIgnoresTerminalState(t *testing.T) {
	seed(t, "DB_USER", "alice")
	asTerminal(t, false)
	out := capture(t)

	if err := Reveal([]string{"DB_USER"}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "alice\n" {
		t.Fatalf("got %q, want %q", got, "alice\n")
	}
}

func TestRevealNULIsByteExact(t *testing.T) {
	// Trailing newlines are exactly what $(...) destroys, so they are the case
	// -0 exists for.
	seed(t, "CERT", "body\n\n\n", "PLAIN", "x")
	asTerminal(t, false)
	out := capture(t)

	if err := Reveal([]string{"-0", "CERT", "PLAIN"}); err != nil {
		t.Fatal(err)
	}
	want := "body\n\n\n\x00x\x00"
	if got := out.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRevealNULFlagAfterKeys(t *testing.T) {
	seed(t, "A", "1")
	out := capture(t)
	if err := Reveal([]string{"A", "-0"}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "1\x00" {
		t.Fatalf("got %q, want %q", got, "1\x00")
	}
}

func TestRevealIsAllOrNothing(t *testing.T) {
	seed(t, "PRESENT", "x")
	out := capture(t)
	err := Reveal([]string{"PRESENT", "NOPE"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("partial reveal leaked %q", out.String())
	}
}

func TestListPrintsNamesTimesAndFingerprints(t *testing.T) {
	seed(t, "ZULU", "z", "ALPHA", "a")
	out := capture(t)

	if err := List(nil); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	if !strings.Contains(got, "NAME") || !strings.Contains(got, "FINGERPRINT") {
		t.Fatalf("missing header: %q", got)
	}
	// Sorted, not insertion order.
	if strings.Index(got, "ALPHA") > strings.Index(got, "ZULU") {
		t.Fatalf("names not sorted: %q", got)
	}
	// No plaintext: `list` needs no approval precisely because of this.
	for _, v := range []string{"\ta\t", "\tz\t", "=a", "=z"} {
		if strings.Contains(got, v) {
			t.Fatalf("list leaked a value (%q): %q", v, got)
		}
	}
	if n := len(regexp.MustCompile(`\b[0-9a-f]{8}\b`).FindAllString(got, -1)); n != 2 {
		t.Fatalf("want 2 eight-hex fingerprints, found %d: %q", n, got)
	}
	if !strings.Contains(got, "Z") { // RFC3339 UTC
		t.Fatalf("timestamps should be UTC RFC3339: %q", got)
	}
}

func TestListOnEmptyAndAbsentVault(t *testing.T) {
	dir := vaultDir(t)
	out := capture(t)

	// Absent vault is an error, not silence.
	if err := List(nil); !errors.Is(err, errs.ErrVaultNotFound) {
		t.Fatalf("want ErrVaultNotFound, got %v", err)
	}

	// A vault that exists but holds nothing prints nothing and succeeds.
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := Delete([]string{"A"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := List(nil); err != nil {
		t.Fatalf("empty vault: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("empty vault printed %q", out.String())
	}
	_ = dir
}

func TestListRejectsArguments(t *testing.T) {
	seed(t, "A", "1")
	capture(t)
	if err := List([]string{"A"}); err == nil {
		t.Fatal("list took a positional argument")
	}
}
