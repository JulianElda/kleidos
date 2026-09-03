package cmd

import (
	"errors"
	"strings"
	"testing"

	"kleidos/internal/errs"
)

func TestHasSucceedsWhenEveryKeyExists(t *testing.T) {
	seed(t, "DB_USER", "alice", "DB_PASSWORD", "hunter2")
	out := capture(t)

	if err := Has([]string{"DB_PASSWORD", "DB_USER"}); err != nil {
		t.Fatalf("both keys exist: %v", err)
	}
	// The answer is the exit status. Anything on stdout would make this a verb
	// callers have to parse, and one that could grow a plaintext path later.
	if out.Len() != 0 {
		t.Fatalf("has wrote %q to stdout", out.String())
	}
}

func TestHasNamesEveryAbsentKey(t *testing.T) {
	seed(t, "PRESENT", "x")
	out := capture(t)

	err := Has([]string{"MISSING_A", "PRESENT", "MISSING_B"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	// The same status and message shape `run` gives, so a caller reads one
	// format for both.
	if errs.Code(err) != errs.KeyNotFound {
		t.Fatalf("want exit %d, got %d", errs.KeyNotFound, errs.Code(err))
	}
	for _, name := range []string{"MISSING_A", "MISSING_B"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should name %s, got: %v", name, err)
		}
	}
	if out.Len() != 0 {
		t.Fatalf("has wrote %q to stdout", out.String())
	}
}

// A vault that cannot be opened is not a vault that lacks the key: a caller that
// treats the two alike provisions over a vault it merely failed to read.
func TestHasSeparatesAnUnreadableVaultFromAnAbsentKey(t *testing.T) {
	vaultDir(t)
	capture(t)

	err := Has([]string{"ANY"})
	if !errors.Is(err, errs.ErrVaultNotFound) {
		t.Fatalf("want ErrVaultNotFound, got %v", err)
	}
	if errs.Code(err) != errs.VaultNotFound {
		t.Fatalf("want exit %d, got %d", errs.VaultNotFound, errs.Code(err))
	}
}

// A name that could never be stored is an error, not a report of absence, which
// a caller would read as the legitimate state it is not.
func TestHasRejectsAnUnstorableKeyName(t *testing.T) {
	seed(t, "PRESENT", "x")
	capture(t)

	err := Has([]string{"lowercase"})
	if err == nil {
		t.Fatal("an invalid key name was reported as merely absent")
	}
	if errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("an invalid name should not read as absence: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid key name") {
		t.Fatalf("error should say the name is invalid, got: %v", err)
	}
}

func TestHasNeedsAKey(t *testing.T) {
	seed(t, "PRESENT", "x")
	capture(t)
	if err := Has(nil); err == nil {
		t.Fatal("has with no keys was accepted")
	}
}
