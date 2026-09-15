package clipboard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The Wayland wire format: a header of the object id and a word packing the
// message size (high 16 bits) with the opcode (low 16), then the arguments,
// each padded to 4 bytes, in host byte order. File descriptors travel out of
// band as SCM_RIGHTS, in the order their messages appear.
//
// Only the handful of messages needed here are spoken. Data-control rather than
// wl_data_device is the protocol because the latter only accepts a selection
// from a client with keyboard focus, and a command-line tool has no surface to
// hold focus with. data-control exists for exactly this -- clipboard managers
// and tools -- and is what wl-copy uses where it is available.
//
// ext-data-control-v1 is the standardised successor of the wlroots protocol;
// the two are opcode-for-opcode identical in every message used here, so one
// code path speaks either.

const wlDisplayID = 1

// Opcodes, by interface.
const (
	displaySync        = 0 // request: callback new_id
	displayGetRegistry = 1 // request: registry new_id
	displayError       = 0 // event: object, code, message

	registryBind   = 0 // request: name, interface, version, new_id
	registryGlobal = 0 // event: name, interface, version

	callbackDone = 0 // event

	managerCreateSource = 0 // request: source new_id
	managerGetDevice    = 1 // request: device new_id, seat

	deviceSetSelection = 0 // request: source (nullable)
	deviceFinished     = 2 // event

	sourceOffer     = 0 // request: mime
	sourceSend      = 0 // event: mime, fd
	sourceCancelled = 1 // event
)

var dataControlManagers = []string{
	"ext_data_control_manager_v1",
	"zwlr_data_control_manager_v1",
}

type wlEvent struct {
	obj  uint32
	op   uint16
	body []byte
	fd   int // -1 unless the event carried one
}

type wlConn struct {
	conn   *net.UnixConn
	buf    []byte // bytes read but not yet framed into events
	fds    []int  // descriptors received but not yet claimed by an event
	nextID uint32
}

// waylandSocket resolves the compositor socket the way libwayland does.
func waylandSocket() (string, error) {
	name := os.Getenv("WAYLAND_DISPLAY")
	if name == "" {
		return "", errors.New("WAYLAND_DISPLAY is unset")
	}
	if filepath.IsAbs(name) {
		return name, nil
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is unset")
	}
	return filepath.Join(dir, name), nil
}

func (w *wlConn) newID() uint32 {
	id := w.nextID
	w.nextID++
	return id
}

// request sends one message. Arguments are uint32 (ints, object ids, new ids,
// and 0 for a null object) or string.
func (w *wlConn) request(obj uint32, op uint16, args ...any) error {
	msg := make([]byte, 8, 64)
	for _, a := range args {
		switch v := a.(type) {
		case uint32:
			msg = binary.NativeEndian.AppendUint32(msg, v)
		case string:
			msg = binary.NativeEndian.AppendUint32(msg, uint32(len(v)+1))
			msg = append(msg, v...)
			msg = append(msg, 0)
			msg = pad4(msg)
		default:
			panic(fmt.Sprintf("wayland: unsupported argument type %T", a))
		}
	}
	binary.NativeEndian.PutUint32(msg[0:], obj)
	binary.NativeEndian.PutUint32(msg[4:], uint32(len(msg))<<16|uint32(op))
	_, err := w.conn.Write(msg)
	return err
}

// next returns the next event. It claims a descriptor only for the one event
// kind here that carries one; every other message is fd-free in the interfaces
// this client binds, so the queue cannot drift out of step.
func (w *wlConn) next(source uint32) (wlEvent, error) {
	for {
		if len(w.buf) >= 8 {
			size := int(binary.NativeEndian.Uint32(w.buf[4:]) >> 16)
			if size < 8 || size%4 != 0 {
				return wlEvent{}, fmt.Errorf("wayland: malformed message of %d bytes", size)
			}
			if len(w.buf) >= size {
				ev := wlEvent{
					obj:  binary.NativeEndian.Uint32(w.buf[0:]),
					op:   uint16(binary.NativeEndian.Uint32(w.buf[4:])),
					body: append([]byte(nil), w.buf[8:size]...),
					fd:   -1,
				}
				w.buf = w.buf[size:]
				if ev.obj == source && source != 0 && ev.op == sourceSend {
					if len(w.fds) == 0 {
						return wlEvent{}, errors.New("wayland: send event arrived without a descriptor")
					}
					ev.fd, w.fds = w.fds[0], w.fds[1:]
				}
				return ev, nil
			}
		}

		b := make([]byte, 4096)
		oob := make([]byte, syscall.CmsgSpace(28*4)) // libwayland's per-message fd cap
		n, oobn, _, _, err := w.conn.ReadMsgUnix(b, oob)
		if err != nil {
			return wlEvent{}, fmt.Errorf("wayland: reading from compositor: %w", err)
		}
		if n == 0 && oobn == 0 {
			return wlEvent{}, errors.New("wayland: compositor closed the connection")
		}
		if oobn > 0 {
			msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				return wlEvent{}, fmt.Errorf("wayland: parsing control message: %w", err)
			}
			for i := range msgs {
				fds, err := syscall.ParseUnixRights(&msgs[i])
				if err == nil {
					w.fds = append(w.fds, fds...)
				}
			}
		}
		w.buf = append(w.buf, b[:n]...)
	}
}

func (w *wlConn) close() {
	for _, fd := range w.fds {
		_ = syscall.Close(fd)
	}
	_ = w.conn.Close()
}

// wlArgs decodes an event body in order.
type wlArgs []byte

func (a *wlArgs) uint() uint32 {
	if len(*a) < 4 {
		*a = nil
		return 0
	}
	v := binary.NativeEndian.Uint32(*a)
	*a = (*a)[4:]
	return v
}

func (a *wlArgs) string() string {
	n := int(a.uint())
	if n == 0 || n > len(*a) {
		*a = nil
		return ""
	}
	s := string((*a)[:n-1])
	*a = (*a)[(n+3)&^3:]
	return s
}

func displayErr(body []byte) error {
	a := wlArgs(body)
	obj, code, msg := a.uint(), a.uint(), a.string()
	return fmt.Errorf("wayland: protocol error on object %d, code %d: %s", obj, code, msg)
}

// roundtrip sends a sync and returns once the compositor has processed
// everything before it, passing every intervening event to handle.
func (w *wlConn) roundtrip(source uint32, handle func(wlEvent) error) error {
	cb := w.newID()
	if err := w.request(wlDisplayID, displaySync, cb); err != nil {
		return err
	}
	for {
		ev, err := w.next(source)
		if err != nil {
			return err
		}
		switch {
		case ev.obj == cb && ev.op == callbackDone:
			return nil
		case ev.obj == wlDisplayID && ev.op == displayError:
			return displayErr(ev.body)
		}
		if err := handle(ev); err != nil {
			return err
		}
	}
}

func serveWayland(ctx context.Context, value []byte, ready func()) error {
	path, err := waylandSocket()
	if err != nil {
		return unavailable("wayland", err)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return unavailable("wayland", err)
	}
	w := &wlConn{conn: conn, nextID: 2}
	defer w.close()

	// Discover the globals. Any failure up to the first offer is a missing
	// backend rather than a failed copy, so X11 still gets its turn.
	registry := w.newID()
	if err := w.request(wlDisplayID, displayGetRegistry, registry); err != nil {
		return unavailable("wayland", err)
	}
	type global struct {
		name, version uint32
		found         bool
	}
	var seat global
	managers := make(map[string]global)
	err = w.roundtrip(0, func(ev wlEvent) error {
		if ev.obj != registry || ev.op != registryGlobal {
			return nil
		}
		a := wlArgs(ev.body)
		name, iface, version := a.uint(), a.string(), a.uint()
		switch {
		case iface == "wl_seat" && !seat.found:
			seat = global{name, version, true}
		case iface == dataControlManagers[0] || iface == dataControlManagers[1]:
			managers[iface] = global{name, version, true}
		}
		return nil
	})
	if err != nil {
		return unavailable("wayland", err)
	}
	if !seat.found {
		return unavailable("wayland", errors.New("compositor advertises no seat"))
	}
	var managerIface string
	for _, iface := range dataControlManagers {
		if managers[iface].found {
			managerIface = iface
			break
		}
	}
	if managerIface == "" {
		return unavailable("wayland", errors.New("compositor does not support data-control"))
	}

	// Version 1 of both is enough: nothing used here was added later.
	seatID, managerID := w.newID(), w.newID()
	source, device := w.newID(), w.newID()
	err = errors.Join(
		w.request(registry, registryBind, seat.name, "wl_seat", uint32(1), seatID),
		w.request(registry, registryBind, managers[managerIface].name, managerIface, uint32(1), managerID),
		w.request(managerID, managerCreateSource, source),
	)
	// The hint goes first so a manager that stops at the first type it
	// recognises sees it before any of the text types.
	for _, typ := range append([]string{passwordHint}, textTypes...) {
		err = errors.Join(err, w.request(source, sourceOffer, typ))
	}
	err = errors.Join(err,
		w.request(managerID, managerGetDevice, device, seatID),
		w.request(device, deviceSetSelection, source),
	)
	if err != nil {
		return fmt.Errorf("wayland: %w", err)
	}

	// The roundtrip is the confirmation: a compositor that rejected any of the
	// above has sent a protocol error by the time the sync comes back. A send
	// can already arrive here, from a clipboard manager reacting at once.
	owned := true
	err = w.roundtrip(source, func(ev wlEvent) error {
		return w.handle(ev, source, device, value, &owned)
	})
	if err != nil {
		return err
	}
	if !owned {
		return errors.New("wayland: the selection was replaced before it could be confirmed")
	}
	ready()

	// Reading blocks, so it moves to a goroutine and the deadline can be
	// selected on. Only this goroutine reads and only the loop below writes.
	events := make(chan wlEvent)
	failed := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			ev, err := w.next(source)
			if err != nil {
				failed <- err
				return
			}
			select {
			case events <- ev:
			case <-stop:
				if ev.fd >= 0 {
					_ = syscall.Close(ev.fd)
				}
				return
			}
		}
	}()

	for owned {
		select {
		case <-ctx.Done():
			// Clear explicitly rather than relying only on the disconnect, and
			// give the compositor a moment to act on it before closing.
			if err := w.request(device, deviceSetSelection, uint32(0)); err != nil {
				return nil
			}
			cb := w.newID()
			if err := w.request(wlDisplayID, displaySync, cb); err != nil {
				return nil
			}
			deadline := time.After(time.Second)
			for {
				select {
				case ev := <-events:
					if ev.obj == cb {
						return nil
					}
					if ev.fd >= 0 {
						_ = syscall.Close(ev.fd)
					}
				case <-failed:
					return nil
				case <-deadline:
					return nil
				}
			}
		case err := <-failed:
			return err
		case ev := <-events:
			if ev.obj == wlDisplayID && ev.op == displayError {
				return displayErr(ev.body)
			}
			if err := w.handle(ev, source, device, value, &owned); err != nil {
				return err
			}
		}
	}
	return nil
}

// handle reacts to the events that concern the offered selection. owned turns
// false when another client has taken the clipboard.
func (w *wlConn) handle(ev wlEvent, source, device uint32, value []byte, owned *bool) error {
	switch {
	case ev.obj == source && ev.op == sourceSend:
		a := wlArgs(ev.body)
		typ := a.string()
		data, ok := payload(value, typ)
		f := os.NewFile(uintptr(ev.fd), "paste")
		// A reader that never drains the pipe must not stall the event loop,
		// or the deadline that clears the clipboard would never be acted on.
		go func() {
			defer func() { _ = f.Close() }()
			if ok {
				_, _ = f.Write(data)
			}
		}()
	case ev.obj == source && ev.op == sourceCancelled:
		*owned = false
	case ev.obj == device && ev.op == deviceFinished:
		return errors.New("wayland: the compositor withdrew the clipboard device")
	}
	return nil
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
