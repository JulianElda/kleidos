package cmd

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"kleidos/internal/errs"
)

// capturedExec records what Run would have exec'd, instead of replacing the
// test process.
type capturedExec struct {
	path   string
	argv   []string
	env    []string
	called bool
}

func interceptExec(t *testing.T) *capturedExec {
	t.Helper()
	var got capturedExec
	old := execve
	execve = func(path string, argv, env []string) error {
		got.called, got.path, got.argv, got.env = true, path, argv, env
		return nil
	}
	t.Cleanup(func() { execve = old })
	return &got
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			return kv[len(key)+1:], true
		}
	}
	return "", false
}

func TestRunRequiresDoubleDash(t *testing.T) {
	seed(t, "A", "1")
	err := Run([]string{"--only", "A", "true"})
	if err == nil {
		t.Fatal("run without -- was accepted")
	}
	if !strings.Contains(err.Error(), "requires --") {
		t.Fatalf("error should name the missing separator, got: %v", err)
	}
}

func TestRunRequiresACommand(t *testing.T) {
	seed(t, "A", "1")
	if err := Run([]string{"--only", "A", "--"}); err == nil {
		t.Fatal("run with nothing after -- was accepted")
	}
}

func TestRunRequiresOnly(t *testing.T) {
	seed(t, "A", "1")
	err := Run([]string{"--", "true"})
	if err == nil {
		t.Fatal("run without --only was accepted")
	}
	if !strings.Contains(err.Error(), "--only") {
		t.Fatalf("error should name --only, got: %v", err)
	}
}

func TestRunOptionalInjectsWhatIsPresent(t *testing.T) {
	seed(t, "REQUIRED", "r", "SOMETIMES", "s")
	got := interceptExec(t)

	if err := Run([]string{"--only", "REQUIRED", "--optional", "SOMETIMES", "--", "true"}); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"REQUIRED": "r", "SOMETIMES": "s"} {
		if v, ok := envValue(got.env, k); !ok || v != want {
			t.Fatalf("env %s = %q (present=%v), want %q", k, v, ok, want)
		}
	}
}

// The case the probe existed for: a key this very command writes later is
// legitimately absent on the first run, and naming it under --only would make
// that run impossible.
func TestRunOptionalKeyMayBeAbsent(t *testing.T) {
	seed(t, "REQUIRED", "r")
	got := interceptExec(t)

	if err := Run([]string{"--only", "REQUIRED", "--optional", "NOT_YET_WRITTEN", "--", "true"}); err != nil {
		t.Fatalf("an absent optional key must not fail the run: %v", err)
	}
	if !got.called {
		t.Fatal("run did not exec")
	}
	if _, ok := envValue(got.env, "NOT_YET_WRITTEN"); ok {
		t.Fatal("an absent optional key was injected anyway")
	}
	if v, _ := envValue(got.env, "REQUIRED"); v != "r" {
		t.Fatalf("REQUIRED = %q", v)
	}
}

// --optional does not weaken --only: a missing required key still fails before
// exec, even when an optional key resolved.
func TestRunOptionalDoesNotWeakenOnly(t *testing.T) {
	seed(t, "SOMETIMES", "s")
	got := interceptExec(t)

	err := Run([]string{"--only", "REQUIRED", "--optional", "SOMETIMES", "--", "true"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	if got.called {
		t.Fatal("run exec'd without a required key")
	}
}

func TestRunAcceptsOptionalWithoutOnly(t *testing.T) {
	seed(t, "SOMETIMES", "s")
	got := interceptExec(t)

	if err := Run([]string{"--optional", "SOMETIMES", "--", "true"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := envValue(got.env, "SOMETIMES"); !ok || v != "s" {
		t.Fatalf("SOMETIMES = %q (present=%v)", v, ok)
	}
}

// A key cannot be both required and survivable.
func TestRunRejectsAKeyInBothLists(t *testing.T) {
	seed(t, "BOTH", "x")
	got := interceptExec(t)

	err := Run([]string{"--only", "BOTH", "--optional", "BOTH", "--", "true"})
	if err == nil {
		t.Fatal("a key named in both lists was accepted")
	}
	if !strings.Contains(err.Error(), "BOTH") {
		t.Fatalf("error should name the key, got: %v", err)
	}
	if got.called {
		t.Fatal("run exec'd on a contradictory request")
	}
}

// A vault written before empty values were refused can still hold them. Injecting
// one is what sends a self-re-execing consumer into a loop, so run refuses --
// naming every offending key, because an older vault can hold several.
func TestRunRefusesEmptyValuesAndNamesThemAll(t *testing.T) {
	dir := seed(t, "REAL", "x")
	seedRaw(t, dir, "OLD_EMPTY_A", "")
	seedRaw(t, dir, "OLD_EMPTY_B", "")
	got := interceptExec(t)

	err := Run([]string{"--only", "OLD_EMPTY_A,REAL,OLD_EMPTY_B", "--", "true"})
	if !errors.Is(err, errs.ErrEmptyValue) {
		t.Fatalf("want ErrEmptyValue, got %v", err)
	}
	for _, name := range []string{"OLD_EMPTY_A", "OLD_EMPTY_B"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should name %s, got: %v", name, err)
		}
	}
	if got.called {
		t.Fatal("run exec'd with an empty value in the child environment")
	}
}

// An optional key that is present but empty is a vault written wrong, not a key
// that is absent, so it fails rather than being quietly skipped -- skipping it
// would hand the child exactly the "unset" it was trying to detect.
func TestRunRefusesAnEmptyOptionalValue(t *testing.T) {
	dir := seed(t, "REAL", "x")
	seedRaw(t, dir, "OLD_EMPTY", "")
	got := interceptExec(t)

	err := Run([]string{"--only", "REAL", "--optional", "OLD_EMPTY", "--", "true"})
	if !errors.Is(err, errs.ErrEmptyValue) {
		t.Fatalf("want ErrEmptyValue, got %v", err)
	}
	if got.called {
		t.Fatal("run exec'd with an empty optional value")
	}
}

func TestRunInjectsIntoEnvNotArgv(t *testing.T) {
	seed(t, "DB_USER", "alice", "DB_PASSWORD", "hunter2")
	got := interceptExec(t)

	if err := Run([]string{"--only", "DB_USER,DB_PASSWORD", "--", "printenv", "DB_USER"}); err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(got.path, "/printenv") {
		t.Fatalf("resolved path = %q", got.path)
	}
	// argv holds the command and its own arguments, never a value: argv is
	// world-readable via /proc/<pid>/cmdline.
	for _, a := range got.argv {
		if a == "alice" || a == "hunter2" {
			t.Fatalf("secret leaked into argv: %v", got.argv)
		}
	}
	if got.argv[0] != "printenv" || got.argv[1] != "DB_USER" {
		t.Fatalf("argv = %v, want [printenv DB_USER]", got.argv)
	}

	for k, want := range map[string]string{"DB_USER": "alice", "DB_PASSWORD": "hunter2"} {
		if v, ok := envValue(got.env, k); !ok || v != want {
			t.Fatalf("env %s = %q (present=%v), want %q", k, v, ok, want)
		}
	}
}

func TestRunInjectsOnlyWhatWasNamed(t *testing.T) {
	seed(t, "WANTED", "yes", "UNWANTED", "no")
	got := interceptExec(t)

	if err := Run([]string{"--only", "WANTED", "--", "true"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := envValue(got.env, "UNWANTED"); ok {
		t.Fatal("run injected a key that was not requested")
	}
	// The rest of the environment is inherited.
	if _, ok := envValue(got.env, "PATH"); !ok {
		t.Fatal("run did not inherit PATH")
	}
}

func TestRunSecretsWinAndShadowingIsReported(t *testing.T) {
	seed(t, "SHADOWED", "from-vault")
	t.Setenv("SHADOWED", "from-environment")
	got := interceptExec(t)

	// The warning goes to stderr; capture it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	runErr := Run([]string{"--only", "SHADOWED", "--", "true"})
	os.Stderr = oldStderr
	_ = w.Close()
	warning := make([]byte, 512)
	n, _ := r.Read(warning)
	_ = r.Close()

	if runErr != nil {
		t.Fatal(runErr)
	}
	if v, _ := envValue(got.env, "SHADOWED"); v != "from-vault" {
		t.Fatalf("SHADOWED = %q, want the vault value to win", v)
	}
	// Exactly one entry: the inherited one is replaced in place, not appended to.
	count := 0
	for _, kv := range got.env {
		if strings.HasPrefix(kv, "SHADOWED=") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("SHADOWED appears %d times in the child env", count)
	}
	if !strings.Contains(string(warning[:n]), "SHADOWED") {
		t.Fatalf("shadowing was not reported on stderr, got: %q", warning[:n])
	}
}

func TestRunFailsBeforeExecOnMissingKey(t *testing.T) {
	seed(t, "PRESENT", "x")
	got := interceptExec(t)

	err := Run([]string{"--only", "PRESENT,MISSING", "--", "true"})
	if !errors.Is(err, errs.ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
	// The command must never start with a blank credential.
	if got.called {
		t.Fatal("run exec'd the command despite a missing key")
	}
}

func TestRunFailsBeforeExecWithoutAVault(t *testing.T) {
	vaultDir(t)
	got := interceptExec(t)
	err := Run([]string{"--only", "A", "--", "true"})
	if !errors.Is(err, errs.ErrVaultNotFound) {
		t.Fatalf("want ErrVaultNotFound, got %v", err)
	}
	if got.called {
		t.Fatal("run exec'd the command despite having no vault")
	}
}

func TestRunCommandNotFound(t *testing.T) {
	seed(t, "A", "1")
	interceptExec(t)
	err := Run([]string{"--only", "A", "--", "kleidos-no-such-command-exists"})
	if errs.Code(err) != errs.NotFound {
		t.Fatalf("want exit %d, got %d (%v)", errs.NotFound, errs.Code(err), err)
	}
}

func TestRunCommandNotExecutable(t *testing.T) {
	seed(t, "A", "1")
	interceptExec(t)

	dir := t.TempDir()
	path := dir + "/not-executable"
	if err := os.WriteFile(path, []byte("#!/bin/sh\ntrue\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := Run([]string{"--only", "A", "--", path})
	if errs.Code(err) != errs.NotExecutable {
		t.Fatalf("want exit %d, got %d (%v)", errs.NotExecutable, errs.Code(err), err)
	}
}

func TestRunRejectsBadKeyNames(t *testing.T) {
	seed(t, "A", "1")
	interceptExec(t)
	for _, only := range []string{"a", "A,", ",A", "A,,B", "A B"} {
		if err := Run([]string{"--only", only, "--", "true"}); err == nil {
			t.Errorf("--only %q was accepted", only)
		}
	}
}

// Our codes start at 120 so that anything below it can only have come from the
// child. 126 and 127 stay reserved for the shell conventions.
func TestRunCodesStayOutOfTheChildRange(t *testing.T) {
	for _, code := range []int{errs.NotExecutable, errs.NotFound} {
		if code < 126 {
			t.Errorf("%d collides with the child's range", code)
		}
	}
	if errs.Generic < 120 || errs.NoTerminal > 125 {
		t.Error("kleidos codes must sit in 120-125")
	}
}

func TestRunPropagatesExecErrors(t *testing.T) {
	seed(t, "A", "1")
	old := execve
	execve = func(string, []string, []string) error { return syscall.EACCES }
	t.Cleanup(func() { execve = old })

	err := Run([]string{"--only", "A", "--", "true"})
	if errs.Code(err) != errs.NotExecutable {
		t.Fatalf("want exit %d, got %d (%v)", errs.NotExecutable, errs.Code(err), err)
	}
}
