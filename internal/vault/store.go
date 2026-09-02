package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"filippo.io/age"

	"kleidos/internal/errs"
)

// Store is the on-disk vault directory.
type Store struct {
	dir    string
	ids    []age.Identity
	recips []age.Recipient // loaded lazily; only writes need them
}

// Open loads the identity. Recipients are deferred until a write needs them, so
// read-only verbs still work if the recipients file is missing.
func Open(dir string) (*Store, error) {
	ids, err := loadIdentities(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, ids: ids}, nil
}

func (s *Store) Dir() string        { return s.dir }
func (s *Store) vaultPath() string  { return filepath.Join(s.dir, "secrets.age") }
func (s *Store) backupPath() string { return s.vaultPath() + ".bak" }
func (s *Store) lockPath() string   { return filepath.Join(s.dir, "lock") }

// Load returns the vault, or ErrVaultNotFound if it does not exist yet.
//
// Reads deliberately take no lock. rename is atomic, so a reader opens either
// the old inode or the new one, whole, and never a torn file. This is a decision,
// not an oversight: locking here would serialize every read against every write
// for no correctness gain, and would let a stuck writer block reads.
func (s *Store) Load() (*Vault, error) {
	v, err := s.load()
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("%w: %s", errs.ErrVaultNotFound, s.vaultPath())
	}
	return v, nil
}

// load returns (nil, nil) when the vault does not exist -- absence is not an
// error on the write path, where the first `set` creates it.
func (s *Store) load() (*Vault, error) {
	f, err := os.Open(s.vaultPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := age.Decrypt(f, s.ids...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errs.ErrDecrypt, err)
	}
	return Decode(r)
}

// Update performs a read-modify-write under an exclusive lock. Every mutation,
// including delete, goes through here: decrypt, mutate, re-encrypt the whole
// blob, replace atomically.
//
// fn receives the existing vault, or a freshly created one if none exists.
func (s *Store) Update(fn func(*Vault) error) error {
	return s.withLock(func() error {
		v, err := s.load()
		if err != nil {
			return err
		}
		if v == nil {
			if v, err = New(); err != nil {
				return err
			}
		}
		if err := fn(v); err != nil {
			return err
		}
		return s.save(v)
	})
}

// withLock is steps 1 and 8 of the write path.
func (s *Store) withLock(fn func() error) error {
	// A separate file from the vault, and NEVER unlinked.
	//
	// Separate, because the vault legitimately does not exist before the first
	// `set`, so locking it races on creation. Never unlinked, because flock locks
	// an inode rather than a path: once one writer unlinks the lock, the next
	// O_CREAT produces a fresh inode, and the two writers then hold exclusive
	// locks on different objects and exclude nobody.
	lf, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("opening lock: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		lf.Close()
		return fmt.Errorf("locking: %w", err)
	}
	err = fn()
	syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	lf.Close()
	return err
}

// save is steps 4 through 7: write a temp file in the same directory, hardlink
// the current vault aside, rename over it, then fsync the directory.
func (s *Store) save(v *Vault) error {
	recips, err := s.recipients()
	if err != nil {
		return err
	}

	secrets, bak := s.vaultPath(), s.backupPath()

	// Step 4. os.CreateTemp already creates with mode 0600, in the same directory
	// so that the later rename stays within one filesystem.
	tmp, err := os.CreateTemp(s.dir, ".secrets-*.tmp")
	if err != nil {
		return err
	}
	// Registered immediately, before anything is written: a failure between here
	// and the rename would otherwise leave a full ciphertext copy behind. After a
	// successful rename this is a harmless ENOENT.
	defer os.Remove(tmp.Name())

	w, err := age.Encrypt(tmp, recips...)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := v.Encode(w); err != nil {
		tmp.Close()
		return err
	}
	// Closing the age writer MUST precede Sync: it flushes the final chunk and
	// the MAC. Syncing first fsyncs an incomplete ciphertext.
	if err := w.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Step 5. Hardlink the current vault aside -- not a copy. Skipped entirely
	// when the vault does not yet exist, since link would return ENOENT on the
	// first write. Stat first rather than branching on the errno.
	//
	// The unlink-then-link is a TOCTOU that is only safe because the lock is sound.
	if _, err := os.Stat(secrets); err == nil {
		if err := os.Remove(bak); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.Link(secrets, bak); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// Step 6. Rename replaces the directory entry without freeing the old inode
	// while .bak still references it, so the previous ciphertext survives. Never
	// *move* the vault to .bak -- that creates a window with neither.
	if err := os.Rename(tmp.Name(), secrets); err != nil {
		return err
	}

	// Step 7. fsync the DIRECTORY, not just the file. Without this the rename may
	// not be durable.
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// recipients loads and caches the recipients file. Every write re-encrypts to
// all of them, which is what makes a break-glass identity and a second machine
// work.
func (s *Store) recipients() ([]age.Recipient, error) {
	if s.recips != nil {
		return s.recips, nil
	}
	p := filepath.Join(s.dir, "recipients")
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errs.ErrIdentity, p, err)
	}
	defer f.Close()

	recips, err := age.ParseRecipients(f)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errs.ErrIdentity, p, err)
	}
	if len(recips) == 0 {
		return nil, fmt.Errorf("%w: %s: no recipients", errs.ErrIdentity, p)
	}
	s.recips = recips
	return recips, nil
}

func loadIdentities(dir string) ([]age.Identity, error) {
	p := filepath.Join(dir, "identity")
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errs.ErrIdentity, p, err)
	}
	defer f.Close()

	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errs.ErrIdentity, p, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: %s: no identities", errs.ErrIdentity, p)
	}
	return ids, nil
}
