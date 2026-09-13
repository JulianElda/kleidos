package vault

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"filippo.io/age"

	"kleidos/internal/errs"
)

func inode(t *testing.T, path string) (ino uint64, nlink uint64) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat did not yield a syscall.Stat_t")
	}
	return st.Ino, uint64(st.Nlink)
}

func TestLoadAbsentVault(t *testing.T) {
	s, _ := newStore(t)
	_, err := s.Load()
	if !errors.Is(err, errs.ErrVaultNotFound) {
		t.Fatalf("want ErrVaultNotFound, got %v", err)
	}
	if errs.Code(err) != errs.VaultNotFound {
		t.Fatalf("want exit %d, got %d", errs.VaultNotFound, errs.Code(err))
	}
}

func TestFirstWriteCreatesVaultAndSkipsBackup(t *testing.T) {
	s, dir := newStore(t)

	if err := s.Update(func(v *Vault) error { return v.Set("A", "1") }); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Step 5 is skipped entirely on the first write: there is nothing to back up,
	// and link() would return ENOENT.
	if _, err := os.Stat(s.backupPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first write should leave no .bak, stat gave: %v", err)
	}
	if got := tempFiles(t, dir); len(got) != 0 {
		t.Fatalf("leftover temp files: %v", got)
	}

	fi, err := os.Stat(s.vaultPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("vault mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, nlink := inode(t, s.vaultPath()); nlink != 1 {
		t.Fatalf("fresh vault link count = %d, want 1", nlink)
	}

	v, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("A"); got.Value != "1" {
		t.Fatalf("A = %q, want 1", got.Value)
	}
}

func TestSecondWriteHardlinksPreviousCiphertext(t *testing.T) {
	s, _ := newStore(t)

	if err := s.Update(func(v *Vault) error { return v.Set("A", "first") }); err != nil {
		t.Fatal(err)
	}
	before, _ := inode(t, s.vaultPath())

	if err := s.Update(func(v *Vault) error { return v.Set("A", "second") }); err != nil {
		t.Fatal(err)
	}

	bakIno, bakLinks := inode(t, s.backupPath())
	newIno, _ := inode(t, s.vaultPath())

	// .bak is a hardlink to the pre-rename inode, not a copy. That the two share
	// an inode is what proves the old ciphertext survived rather than being
	// rewritten: rename replaced the directory entry while .bak still referenced
	// the inode, so it was never freed.
	//
	// The link count goes 1 -> 2 -> 1 across the save. The transient 2 is not
	// observable from outside the write, but a shared inode here implies it: both
	// names referenced this inode between the link and the rename.
	if bakIno != before {
		t.Fatalf(".bak inode = %d, want the pre-rename vault inode %d", bakIno, before)
	}
	if newIno == before {
		t.Fatal("vault inode unchanged; the file was rewritten in place, not renamed over")
	}
	if bakLinks != 1 {
		t.Fatalf(".bak link count = %d, want 1 after the rename", bakLinks)
	}

	// The current vault holds the new value; .bak still holds the old ciphertext.
	v, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("A"); got.Value != "second" {
		t.Fatalf("A = %q, want second", got.Value)
	}

	f, err := os.Open(s.backupPath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := age.Decrypt(f, s.ids...)
	if err != nil {
		t.Fatalf("decrypting .bak: %v", err)
	}
	old, err := Decode(r)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := old.Get("A"); got.Value != "first" {
		t.Fatalf(".bak holds A = %q, want first", got.Value)
	}
}

func TestEncryptsToEveryRecipient(t *testing.T) {
	dir := scratchDir(t)
	// Three identities, all three public keys in recipients: the break-glass
	// backup and second-machine shape.
	ids := writeKeys(t, dir, 3)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(v *Vault) error { return v.Set("A", "shared") }); err != nil {
		t.Fatal(err)
	}

	for i, id := range ids {
		f, err := os.Open(s.vaultPath())
		if err != nil {
			t.Fatal(err)
		}
		r, err := age.Decrypt(f, id)
		if err != nil {
			_ = f.Close()
			t.Fatalf("identity %d could not decrypt: %v", i, err)
		}
		v, err := Decode(r)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := v.Get("A"); got.Value != "shared" {
			t.Fatalf("identity %d read A = %q", i, got.Value)
		}
	}
}

func TestUpdateAbortLeavesVaultAndDirectoryClean(t *testing.T) {
	s, dir := newStore(t)
	if err := s.Update(func(v *Vault) error { return v.Set("A", "keep") }); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("caller changed its mind")
	if err := s.Update(func(v *Vault) error {
		if err := v.Set("A", "clobbered"); err != nil {
			return err
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("want the caller's error back, got %v", err)
	}

	v, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get("A"); got.Value != "keep" {
		t.Fatalf("aborted update was persisted: A = %q", got.Value)
	}
	if got := tempFiles(t, dir); len(got) != 0 {
		t.Fatalf("aborted update left temp files: %v", got)
	}
}

func TestLockFileIsCreatedAndNeverRemoved(t *testing.T) {
	s, dir := newStore(t)
	for range 3 {
		if err := s.Update(func(v *Vault) error { return v.Set("A", "x") }); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, "lock"))
	if err != nil {
		t.Fatalf("lock file must survive every write: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("lock mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestOpenWithoutIdentity(t *testing.T) {
	dir := scratchDir(t)
	_, err := Open(dir)
	if !errors.Is(err, errs.ErrIdentity) {
		t.Fatalf("want ErrIdentity, got %v", err)
	}
	if errs.Code(err) != errs.Identity {
		t.Fatalf("want exit %d, got %d", errs.Identity, errs.Code(err))
	}
}

func TestWriteWithoutRecipients(t *testing.T) {
	dir := scratchDir(t)
	writeKeys(t, dir, 1)
	if err := os.Remove(filepath.Join(dir, "recipients")); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("reads should still open without recipients: %v", err)
	}
	err = s.Update(func(v *Vault) error { return v.Set("A", "1") })
	if !errors.Is(err, errs.ErrIdentity) {
		t.Fatalf("want ErrIdentity naming recipients, got %v", err)
	}
	if got := tempFiles(t, dir); len(got) != 0 {
		t.Fatalf("failed write left temp files: %v", got)
	}
}
