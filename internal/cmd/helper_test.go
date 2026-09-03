package cmd

import (
	"os"
	"testing"

	"kleidos/internal/testenv"
	"kleidos/internal/vault"
)

// vaultDir returns a scratch vault directory and points KLEIDOS_DIR at it, so
// the verbs under test never touch the real vault.
func vaultDir(t *testing.T) string {
	t.Helper()
	dir := testenv.Vault(t)
	t.Setenv("KLEIDOS_DIR", dir)
	return dir
}

// withStdin replaces os.Stdin with a pipe carrying data, for --stdin paths.
func withStdin(t *testing.T, data string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	go func() {
		w.WriteString(data)
		w.Close()
	}()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		r.Close()
	})
}

// read opens the vault in dir directly, bypassing the verbs.
func read(t *testing.T, dir string) *vault.Vault {
	t.Helper()
	s, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	v, err := s.Load()
	if err != nil {
		t.Fatalf("loading vault: %v", err)
	}
	return v
}

// value returns the stored value for key, failing if it is absent.
func value(t *testing.T, dir, key string) string {
	t.Helper()
	s, ok := read(t, dir).Get(key)
	if !ok {
		t.Fatalf("%s is absent", key)
	}
	return s.Value
}

// setStdin stores key from a --stdin read of data.
func setStdin(t *testing.T, key, data string) error {
	t.Helper()
	withStdin(t, data)
	return Set([]string{"--stdin", key})
}

// seedRaw writes a value straight into the vault, bypassing Vault.Set. It is how
// a test reaches a state the write paths refuse: a vault written by a kleidos
// that predates a rule, or by something that is not kleidos at all. The store
// must already exist.
func seedRaw(t *testing.T, dir, key, value string) {
	t.Helper()
	s, err := vault.Open(dir)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	err = s.Update(func(v *vault.Vault) error {
		v.Secrets[key] = &vault.Secret{Value: value}
		return nil
	})
	if err != nil {
		t.Fatalf("seeding %s: %v", key, err)
	}
}
