package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// Dir resolves the vault directory: $KLEIDOS_DIR, else $XDG_DATA_HOME/kleidos,
// else ~/.local/share/kleidos.
//
// KLEIDOS_DIR exists so tests can exercise the real binary without touching the
// user's vault. Nothing in this directory may enter /nix/store -- the identity
// stays imperative even if configuration later becomes declarative.
func Dir() (string, error) {
	if d := os.Getenv("KLEIDOS_DIR"); d != "" {
		return d, nil
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "kleidos"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "kleidos"), nil
}
