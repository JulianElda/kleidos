// Package testenv provides scratch directories and key material for tests.
//
// It exists as a real package rather than a _test.go helper so that the vault
// and cmd test suites share one definition of "a usable vault directory".
package testenv

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"filippo.io/age"
)

// tmpfsMagic identifies tmpfs to statfs(2).
const tmpfsMagic = 0x01021994

// ScratchDir returns an empty directory on a real filesystem.
//
// t.TempDir() is unusable for the write path: it lives under /tmp, which is
// tmpfs on the development machine, and fsync on tmpfs succeeds without doing
// anything. That makes steps 4 and 7 of the write path unverifiable -- the race
// half of a concurrency test stays valid, but the durability half becomes
// theatre. Override the base with KLEIDOS_TEST_SCRATCH.
func ScratchDir(t *testing.T) string {
	t.Helper()

	base := os.Getenv("KLEIDOS_TEST_SCRATCH")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("locating home: %v", err)
		}
		base = filepath.Join(home, ".cache", "kleidos-test")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatalf("creating scratch base: %v", err)
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(base, &st); err != nil {
		t.Fatalf("statfs %s: %v", base, err)
	}
	if st.Type == tmpfsMagic {
		t.Fatalf("scratch %s is tmpfs; fsync there is a no-op, so write-path "+
			"durability is unverifiable. Set KLEIDOS_TEST_SCRATCH to a directory "+
			"on a real filesystem.", base)
	}

	dir, err := os.MkdirTemp(base, "kleidos-*")
	if err != nil {
		t.Fatalf("creating scratch dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// WriteKeys generates n identities in dir, writing the first as the identity
// file and all n public keys to recipients -- the break-glass and second-machine
// shape, where every write must re-encrypt to every recipient.
func WriteKeys(t *testing.T, dir string, n int) []*age.X25519Identity {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("creating vault dir: %v", err)
	}

	var ids []*age.X25519Identity
	var recips string
	for range n {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generating identity: %v", err)
		}
		ids = append(ids, id)
		recips += id.Recipient().String() + "\n"
	}

	if err := os.WriteFile(filepath.Join(dir, "identity"), []byte(ids[0].String()+"\n"), 0600); err != nil {
		t.Fatalf("writing identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "recipients"), []byte(recips), 0644); err != nil {
		t.Fatalf("writing recipients: %v", err)
	}
	return ids
}

// Vault returns a scratch directory that already holds a single identity and its
// matching recipients file.
func Vault(t *testing.T) string {
	t.Helper()
	dir := ScratchDir(t)
	WriteKeys(t, dir, 1)
	return dir
}

// TempFiles lists leftover write-path temp files in dir.
func TempFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".secrets-*.tmp"))
	if err != nil {
		t.Fatalf("globbing temp files: %v", err)
	}
	return matches
}
