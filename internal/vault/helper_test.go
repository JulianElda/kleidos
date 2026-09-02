package vault

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"filippo.io/age"
)

// tmpfsMagic identifies tmpfs to statfs(2).
const tmpfsMagic = 0x01021994

// scratchDir returns an empty directory on a real filesystem.
//
// t.TempDir() is unusable here: it lives under /tmp, which is tmpfs on this
// machine, and fsync on tmpfs succeeds without doing anything. That makes steps
// 4 and 7 of the write path unverifiable -- the race half of a concurrency test
// stays valid, but the durability half becomes theatre.
func scratchDir(t *testing.T) string {
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

	dir, err := os.MkdirTemp(base, "vault-*")
	if err != nil {
		t.Fatalf("creating scratch dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// newStore builds a scratch vault directory with a fresh identity and returns an
// open Store over it.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := scratchDir(t)
	writeKeys(t, dir, 1)
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	return s, dir
}

// writeKeys generates n identities, writing the first as the identity file and
// all n public keys to recipients -- the break-glass and second-machine shape.
func writeKeys(t *testing.T, dir string, n int) []*age.X25519Identity {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("creating vault dir: %v", err)
	}

	var ids []*age.X25519Identity
	var recips string
	for i := 0; i < n; i++ {
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

// tempFiles lists leftover write-path temp files in dir.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".secrets-*.tmp"))
	if err != nil {
		t.Fatalf("globbing temp files: %v", err)
	}
	return matches
}
