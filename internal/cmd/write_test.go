package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"kleidos/internal/errs"
	"kleidos/internal/testenv"
)

func TestSetStdinRoundTrip(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "DB_USER", "alice"); err != nil {
		t.Fatal(err)
	}
	if got := value(t, dir, "DB_USER"); got != "alice" {
		t.Fatalf("DB_USER = %q, want alice", got)
	}
}

// A trailing newline is stored verbatim. Certificate and key material
// legitimately ends with one, and silently stripping it is the same class of bug
// as $(...) eating it on the way out.
func TestSetStdinPreservesTrailingNewline(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "CERT", "line\n\n"); err != nil {
		t.Fatal(err)
	}
	if got := value(t, dir, "CERT"); got != "line\n\n" {
		t.Fatalf("CERT = %q, want %q", got, "line\n\n")
	}
}

func TestSetStdinEmptyValue(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "EMPTY", ""); err != nil {
		t.Fatal(err)
	}
	// Present with an empty value is a different state from absent.
	s, ok := read(t, dir).Get("EMPTY")
	if !ok {
		t.Fatal("EMPTY should be present")
	}
	if s.Value != "" {
		t.Fatalf("EMPTY = %q, want empty", s.Value)
	}
}

func TestSetRejectsNUL(t *testing.T) {
	dir := vaultDir(t)
	err := setStdin(t, "K", "a\x00b")
	if !errors.Is(err, errs.ErrNUL) {
		t.Fatalf("want ErrNUL, got %v", err)
	}
	// The vault must not have been created by a rejected write.
	if got := testenv.TempFiles(t, dir); len(got) != 0 {
		t.Fatalf("rejected write left temp files: %v", got)
	}
}

func TestSetRejectsBadKeyNames(t *testing.T) {
	vaultDir(t)
	for _, key := range []string{"db_user", "1DB", "DB-USER", "DB USER", ""} {
		if err := setStdin(t, key, "x"); err == nil {
			t.Errorf("set %q was accepted", key)
		}
	}
}

func TestSetRefusesPositionalValue(t *testing.T) {
	vaultDir(t)
	// argv is world-readable, so there is deliberately no positional value form.
	err := Set([]string{"KEY", "hunter2"})
	if err == nil {
		t.Fatal("set KEY VALUE was accepted")
	}
	if !strings.Contains(err.Error(), "exactly one key") {
		t.Fatalf("error should explain the arity, got: %v", err)
	}
}

func TestDeleteRemovesKey(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := setStdin(t, "B", "2"); err != nil {
		t.Fatal(err)
	}
	if err := Delete([]string{"A"}); err != nil {
		t.Fatal(err)
	}
	v := read(t, dir)
	if _, ok := v.Get("A"); ok {
		t.Fatal("A survived delete")
	}
	if _, ok := v.Get("B"); !ok {
		t.Fatal("delete removed the wrong key")
	}
}

func TestDeleteMissingKey(t *testing.T) {
	vaultDir(t)
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	err := Delete([]string{"NOPE"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	if errs.Code(err) != errs.KeyNotFound {
		t.Fatalf("want exit %d, got %d", errs.KeyNotFound, errs.Code(err))
	}
}

func TestRenamePreservesUpdatedTime(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "OLD", "v"); err != nil {
		t.Fatal(err)
	}
	before, _ := read(t, dir).Get("OLD")
	stamp := before.Updated

	// Ensure a rename that reset the clock would be visible.
	time.Sleep(1100 * time.Millisecond)

	if err := Rename([]string{"OLD", "NEW"}); err != nil {
		t.Fatal(err)
	}
	v := read(t, dir)
	if _, ok := v.Get("OLD"); ok {
		t.Fatal("OLD survived rename")
	}
	after, ok := v.Get("NEW")
	if !ok {
		t.Fatal("NEW is absent after rename")
	}
	if after.Value != "v" {
		t.Fatalf("NEW = %q, want v", after.Value)
	}
	// The value did not change, only its name. Resetting the timestamp would
	// destroy the one staleness signal available.
	if !after.Updated.Equal(stamp) {
		t.Fatalf("rename reset updated: %v -> %v", stamp, after.Updated)
	}
}

func TestRenameRefusesCollision(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "OLD", "keep-me"); err != nil {
		t.Fatal(err)
	}
	if err := setStdin(t, "NEW", "live-credential"); err != nil {
		t.Fatal(err)
	}

	err := Rename([]string{"OLD", "NEW"})
	if err == nil {
		t.Fatal("rename over an existing key was allowed")
	}
	if !strings.Contains(err.Error(), "NEW") {
		t.Fatalf("error should name the collision, got: %v", err)
	}

	// Nothing may have moved.
	v := read(t, dir)
	if got, _ := v.Get("NEW"); got.Value != "live-credential" {
		t.Fatalf("NEW was clobbered: %q", got.Value)
	}
	if _, ok := v.Get("OLD"); !ok {
		t.Fatal("OLD disappeared despite the refusal")
	}
}

func TestRenameForceClobbers(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "OLD", "winner"); err != nil {
		t.Fatal(err)
	}
	if err := setStdin(t, "NEW", "loser"); err != nil {
		t.Fatal(err)
	}
	if err := Rename([]string{"--force", "OLD", "NEW"}); err != nil {
		t.Fatal(err)
	}
	v := read(t, dir)
	if got, _ := v.Get("NEW"); got.Value != "winner" {
		t.Fatalf("NEW = %q, want winner", got.Value)
	}
	if _, ok := v.Get("OLD"); ok {
		t.Fatal("OLD survived a forced rename")
	}
}

func TestRenameMissingSource(t *testing.T) {
	vaultDir(t)
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	err := Rename([]string{"NOPE", "OTHER"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
}

func TestRenameToSameKey(t *testing.T) {
	vaultDir(t)
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := Rename([]string{"A", "A"}); err == nil {
		t.Fatal("rename A A was accepted")
	}
}

func TestRenameRejectsBadTargetName(t *testing.T) {
	vaultDir(t)
	if err := setStdin(t, "A", "1"); err != nil {
		t.Fatal(err)
	}
	if err := Rename([]string{"A", "bad-name"}); err == nil {
		t.Fatal("rename to an invalid key name was accepted")
	}
}

// The documented spelling puts the flag after the key. Go's flag package stops
// parsing at the first positional, so this ordering needs explicit support and
// is easy to regress.
func TestSetFlagAfterKey(t *testing.T) {
	dir := vaultDir(t)
	withStdin(t, "alice")
	if err := Set([]string{"DB_USER", "--stdin"}); err != nil {
		t.Fatalf("set KEY --stdin: %v", err)
	}
	if got := value(t, dir, "DB_USER"); got != "alice" {
		t.Fatalf("DB_USER = %q, want alice", got)
	}
}

func TestRenameFlagAfterKeys(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "OLD", "winner"); err != nil {
		t.Fatal(err)
	}
	if err := setStdin(t, "NEW", "loser"); err != nil {
		t.Fatal(err)
	}
	if err := Rename([]string{"OLD", "NEW", "--force"}); err != nil {
		t.Fatalf("rename OLD NEW --force: %v", err)
	}
	if got := value(t, dir, "NEW"); got != "winner" {
		t.Fatalf("NEW = %q, want winner", got)
	}
}

// A key that looks like a flag must still be usable after --.
func TestSetKeyAfterDoubleDash(t *testing.T) {
	dir := vaultDir(t)
	withStdin(t, "v")
	if err := Set([]string{"--stdin", "--", "A"}); err != nil {
		t.Fatalf("set --stdin -- A: %v", err)
	}
	if got := value(t, dir, "A"); got != "v" {
		t.Fatalf("A = %q, want v", got)
	}
}
