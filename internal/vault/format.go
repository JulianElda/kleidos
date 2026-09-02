package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"kleidos/internal/errs"
)

// Version is the only vault format this build understands. An unrecognized
// version is refused rather than guessed at.
const Version = 1

// Secret is an object rather than a bare string so that metadata can be added
// later without a breaking format migration.
type Secret struct {
	Value   string    `json:"value"`
	Updated time.Time `json:"updated"`
}

// Vault is the plaintext inside the age envelope. All metadata lives in here:
// there is no plaintext index, so `list` requires the identity. Key names leak
// plenty on their own.
type Vault struct {
	Version int                `json:"version"`
	FPKey   []byte             `json:"fpkey"` // marshals as base64
	Secrets map[string]*Secret `json:"secrets"`
}

var keyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// CheckKey enforces the key-name constraint. It is applied on every write, and
// again at export time -- the left-hand side of an eval'ed assignment is its own
// injection point, and trusting the blob assumes every past write enforced this.
func CheckKey(k string) error {
	if !keyRE.MatchString(k) {
		return fmt.Errorf("invalid key name %q: must match [A-Z_][A-Z0-9_]*", k)
	}
	return nil
}

// CheckValue rejects NUL. This is enforced at the write paths -- `set` and
// `import` -- so that "no value contains NUL" is an invariant every consumer can
// rely on, rather than a check each consumer must remember. A NUL breaks both a
// shell variable and an environ entry, so there is no downstream that tolerates it.
func CheckValue(v string) error {
	if strings.IndexByte(v, 0) >= 0 {
		return errs.ErrNUL
	}
	return nil
}

// New returns an empty vault with a freshly generated fingerprint key.
func New() (*Vault, error) {
	fp := make([]byte, 32)
	if _, err := rand.Read(fp); err != nil {
		return nil, fmt.Errorf("generating fingerprint key: %w", err)
	}
	return &Vault{Version: Version, FPKey: fp, Secrets: map[string]*Secret{}}, nil
}

// Set validates and stores a value, stamping the update time.
func (v *Vault) Set(key, value string) error {
	if err := CheckKey(key); err != nil {
		return err
	}
	if err := CheckValue(value); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	v.Secrets[key] = &Secret{Value: value, Updated: now()}
	return nil
}

// Get reports whether key is present, distinguishing absence from an empty value.
func (v *Vault) Get(key string) (*Secret, bool) {
	s, ok := v.Secrets[key]
	return s, ok
}

// Names returns every key, sorted.
func (v *Vault) Names() []string {
	names := make([]string, 0, len(v.Secrets))
	for k := range v.Secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Missing returns those of keys that are absent, in the order given. Multi-key
// reads are all-or-nothing: returning a username with an empty password is the
// dangerous outcome, so callers report every missing name at once.
func (v *Vault) Missing(keys []string) []string {
	var missing []string
	for _, k := range keys {
		if _, ok := v.Secrets[k]; !ok {
			missing = append(missing, k)
		}
	}
	return missing
}

// Fingerprint is HMAC-SHA256(fpkey, value) truncated to 8 hex characters.
//
// Keyed, not a plain digest. `list` runs freely and needs no approval, so a bare
// hash would make it a confirmation oracle: any low-entropy secret -- a PIN, a
// short passphrase, a value from a known set -- falls to trivial offline brute
// force. Keying with fpkey makes the digest meaningless to anyone who cannot
// already decrypt the vault, which is the property fingerprints actually need:
// confirming two machines hold the same value, or that a write landed.
func (v *Vault) Fingerprint(value string) string {
	m := hmac.New(sha256.New, v.FPKey)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil)[:4])
}

// now is a variable so tests can pin the clock.
var now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }

// Decode reads a vault, refusing an unrecognized version rather than guessing.
func Decode(r io.Reader) (*Vault, error) {
	var v Vault
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return nil, fmt.Errorf("vault is corrupt: %w", err)
	}
	if v.Version != Version {
		return nil, fmt.Errorf("unsupported vault version %d; this build understands version %d", v.Version, Version)
	}
	if len(v.FPKey) == 0 {
		return nil, errors.New("vault is corrupt: missing fpkey")
	}
	if v.Secrets == nil {
		v.Secrets = map[string]*Secret{}
	}
	return &v, nil
}

// Encode writes the vault. encoding/json sorts map keys, which satisfies the
// sorted-key requirement without further work.
func (v *Vault) Encode(w io.Writer) error {
	v.Version = Version
	return json.NewEncoder(w).Encode(v)
}
