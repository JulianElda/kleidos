// Package clipboard puts a value on the desktop clipboard by speaking the
// display server's wire protocol directly: Wayland data-control first, X11
// selections second. Nothing is executed and nothing needs to be installed.
//
// On Linux the clipboard is not a store. Whoever copied last owns the selection
// and must stay connected to hand the bytes to each paste, so Serve blocks for
// as long as the value should remain pasteable. Ownership belongs to the
// connection, which is what makes clearing reliable: when the process exits,
// however it exits, the display server drops the selection.
package clipboard

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrUnavailable means no display server could be used at all -- no session,
// or one without any protocol this package speaks.
var ErrUnavailable = errors.New("no usable clipboard")

// backendError marks a failure that happened before anything was offered, so
// the next backend may still be tried. Any other error is final.
type backendError struct {
	backend string
	err     error
}

func (e *backendError) Error() string { return e.backend + ": " + e.err.Error() }
func (e *backendError) Unwrap() error { return e.err }

func unavailable(backend string, err error) error {
	return &backendError{backend, err}
}

// passwordHint is the MIME type, and X11 target, that marks a selection as a
// password. Klipper and wl-paste --watch based managers skip recording it.
// The payload is fixed by convention.
const (
	passwordHint        = "x-kde-passwordManagerHint"
	passwordHintPayload = "secret"
)

// textTypes are the names a paste may ask for the value under: MIME types for
// Wayland clients, the X11 target atoms for X clients, which also reach
// Wayland ones through XWayland's translation.
var textTypes = []string{
	"text/plain;charset=utf-8",
	"text/plain",
	"UTF8_STRING",
	"STRING",
	"TEXT",
}

// payload returns what to send for a requested type, and whether the type is
// one this package offers.
func payload(value []byte, typ string) ([]byte, bool) {
	if typ == passwordHint {
		return []byte(passwordHintPayload), true
	}
	for _, t := range textTypes {
		if t == typ {
			return value, true
		}
	}
	return nil, false
}

// Serve takes the clipboard selection with value and serves pastes until ctx
// is done, at which point it clears the selection if it still owns it, or
// until another client copies something, which ends ownership on its own.
//
// ready is called exactly once, after ownership is confirmed and before any
// paste is served. An error returned without ready having been called means
// the value never reached the clipboard.
func Serve(ctx context.Context, value []byte, ready func()) error {
	if len(value) == 0 {
		return errors.New("refusing to copy an empty value")
	}

	var tried []string
	for _, backend := range []func(context.Context, []byte, func()) error{
		serveWayland,
		serveX11,
	} {
		err := backend(ctx, value, ready)
		var be *backendError
		if !errors.As(err, &be) {
			return err
		}
		tried = append(tried, be.Error())
	}
	return fmt.Errorf("%w (%s)", ErrUnavailable, strings.Join(tried, "; "))
}
