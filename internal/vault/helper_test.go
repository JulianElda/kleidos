package vault

import (
	"testing"

	"filippo.io/age"

	"kleidos/internal/testenv"
)

func scratchDir(t *testing.T) string { t.Helper(); return testenv.ScratchDir(t) }

func writeKeys(t *testing.T, dir string, n int) []*age.X25519Identity {
	t.Helper()
	return testenv.WriteKeys(t, dir, n)
}

func tempFiles(t *testing.T, dir string) []string { t.Helper(); return testenv.TempFiles(t, dir) }

// newStore builds a scratch vault directory with a fresh identity and returns an
// open Store over it.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := testenv.Vault(t)
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	return s, dir
}
