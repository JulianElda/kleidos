package clipboard

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// The X11 core protocol, spoken little-endian (the client picks the order in
// the setup request), over the local Unix socket only. Requests are a 4-byte
// header -- opcode, one data byte, length in 4-byte words -- then the body.
// Replies, errors and events arrive as 32-byte packets; replies say how much
// longer they are.
//
// Serving a selection follows ICCCM: take ownership with a real server
// timestamp, answer each SelectionRequest by writing a property on the
// requestor's window and sending it a SelectionNotify, and stop when a
// SelectionClear says someone else owns it now.

const (
	xCreateWindow      = 1
	xChangeProperty    = 18
	xInternAtom        = 16
	xSetSelectionOwner = 22
	xGetSelectionOwner = 23
	xSendEvent         = 25

	xError            = 0
	xReply            = 1
	xPropertyNotify   = 28
	xSelectionClear   = 29
	xSelectionRequest = 30
	xSelectionNotify  = 31
	xGenericEvent     = 35

	// Predefined atoms.
	atomATOM   = 4
	atomSTRING = 31
	atomWMName = 39

	propModeReplace = 0
	propModeAppend  = 2

	classInputOnly     = 2
	cwEventMask        = 1 << 11
	propertyChangeMask = 1 << 22
)

// x11SocketDir is indirected for tests.
var x11SocketDir = "/tmp/.X11-unix"

type x11Conn struct {
	conn    net.Conn
	seq     uint16
	root    uint32
	window  uint32
	maxReq  int      // largest request, in bytes
	pending [][]byte // events that arrived while waiting for a reply
}

// x11Display parses DISPLAY into its display number. Only local displays are
// supported; a TCP display would put the value on the network in the clear.
func x11Display() (string, error) {
	d := os.Getenv("DISPLAY")
	if d == "" {
		return "", errors.New("DISPLAY is unset")
	}
	host, rest, ok := strings.Cut(d, ":")
	if !ok || (host != "" && host != "unix") {
		return "", fmt.Errorf("DISPLAY=%q is not a local display", d)
	}
	num, _, _ := strings.Cut(rest, ".")
	if num == "" || strings.Trim(num, "0123456789") != "" {
		return "", fmt.Errorf("DISPLAY=%q is malformed", d)
	}
	return num, nil
}

// xauthCookie finds the MIT-MAGIC-COOKIE-1 for a local display number in an
// Xauthority file. Absence is not an error: servers may admit local clients by
// uid, and if not, setup says so.
func xauthCookie(r io.Reader, hostname, display string) (name string, data []byte) {
	const (
		familyLocal = 256
		familyWild  = 65535
	)
	b, err := io.ReadAll(r)
	if err != nil {
		return "", nil
	}
	field := func() ([]byte, bool) {
		if len(b) < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+n {
			return nil, false
		}
		f := b[2 : 2+n]
		b = b[2+n:]
		return f, true
	}
	for len(b) >= 2 {
		family := binary.BigEndian.Uint16(b)
		b = b[2:]
		addr, ok1 := field()
		num, ok2 := field()
		auth, ok3 := field()
		cookie, ok4 := field()
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return "", nil
		}
		hostMatch := family == familyWild || (family == familyLocal && string(addr) == hostname)
		numMatch := len(num) == 0 || string(num) == display
		if hostMatch && numMatch && string(auth) == "MIT-MAGIC-COOKIE-1" {
			return string(auth), cookie
		}
	}
	return "", nil
}

func dialX11() (*x11Conn, error) {
	num, err := x11Display()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(x11SocketDir, "X"+num)
	conn, err := net.Dial("unix", path)
	if err != nil {
		// Some servers listen only on the abstract socket.
		var abstractErr error
		conn, abstractErr = net.Dial("unix", "@"+path)
		if abstractErr != nil {
			return nil, err
		}
	}

	authFile := os.Getenv("XAUTHORITY")
	if authFile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			authFile = filepath.Join(home, ".Xauthority")
		}
	}
	var authName string
	var authData []byte
	if f, err := os.Open(authFile); err == nil {
		hostname, _ := os.Hostname()
		authName, authData = xauthCookie(f, hostname, num)
		_ = f.Close()
	}

	x := &x11Conn{conn: conn}
	if err := x.setup(authName, authData); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return x, nil
}

func (x *x11Conn) setup(authName string, authData []byte) error {
	req := []byte{'l', 0}
	req = binary.LittleEndian.AppendUint16(req, 11) // protocol major
	req = binary.LittleEndian.AppendUint16(req, 0)  // minor
	req = binary.LittleEndian.AppendUint16(req, uint16(len(authName)))
	req = binary.LittleEndian.AppendUint16(req, uint16(len(authData)))
	req = append(req, 0, 0)
	req = pad4(append(req, authName...))
	req = pad4(append(req, authData...))
	if _, err := x.conn.Write(req); err != nil {
		return err
	}

	head := make([]byte, 8)
	if _, err := io.ReadFull(x.conn, head); err != nil {
		return fmt.Errorf("reading setup reply: %w", err)
	}
	body := make([]byte, 4*int(binary.LittleEndian.Uint16(head[6:])))
	if _, err := io.ReadFull(x.conn, body); err != nil {
		return fmt.Errorf("reading setup reply: %w", err)
	}
	switch head[0] {
	case 1:
	case 0:
		reason := body[:min(int(head[1]), len(body))]
		return fmt.Errorf("server refused the connection: %s", strings.TrimSpace(string(reason)))
	default:
		return errors.New("server demands further authentication")
	}

	if len(body) < 32 {
		return errors.New("setup reply is truncated")
	}
	idBase := binary.LittleEndian.Uint32(body[4:])
	vendorLen := int(binary.LittleEndian.Uint16(body[16:]))
	x.maxReq = 4 * int(binary.LittleEndian.Uint16(body[18:]))
	formats := int(body[21])
	screen := 32 + (vendorLen+3)&^3 + 8*formats
	if body[20] == 0 || len(body) < screen+4 {
		return errors.New("setup reply lists no screen")
	}
	x.root = binary.LittleEndian.Uint32(body[screen:])
	x.window = idBase | 1
	return nil
}

func (x *x11Conn) request(op, data byte, body []byte) (uint16, error) {
	body = pad4(body)
	msg := []byte{op, data}
	msg = binary.LittleEndian.AppendUint16(msg, uint16((4+len(body))/4))
	msg = append(msg, body...)
	if _, err := x.conn.Write(msg); err != nil {
		return 0, err
	}
	x.seq++
	return x.seq, nil
}

// packet reads one reply, error or event.
func (x *x11Conn) packet() ([]byte, error) {
	p := make([]byte, 32)
	if _, err := io.ReadFull(x.conn, p); err != nil {
		return nil, err
	}
	if p[0] == xReply || p[0]&0x7f == xGenericEvent {
		extra := make([]byte, 4*int(binary.LittleEndian.Uint32(p[4:])))
		if _, err := io.ReadFull(x.conn, extra); err != nil {
			return nil, err
		}
		p = append(p, extra...)
	}
	return p, nil
}

// reply waits for the answer to request seq, setting events aside.
func (x *x11Conn) reply(seq uint16) ([]byte, error) {
	for {
		p, err := x.packet()
		if err != nil {
			return nil, err
		}
		switch {
		case (p[0] == xReply || p[0] == xError) && binary.LittleEndian.Uint16(p[2:]) == seq:
			if p[0] == xError {
				return nil, fmt.Errorf("request failed with X error %d", p[1])
			}
			return p, nil
		case p[0] != xReply && p[0] != xError:
			x.pending = append(x.pending, p)
		}
	}
}

func (x *x11Conn) internAtom(name string) (uint32, error) {
	body := binary.LittleEndian.AppendUint16(nil, uint16(len(name)))
	body = append(body, 0, 0)
	body = append(body, name...)
	seq, err := x.request(xInternAtom, 0, body)
	if err != nil {
		return 0, err
	}
	p, err := x.reply(seq)
	if err != nil {
		return 0, fmt.Errorf("interning %s: %w", name, err)
	}
	return binary.LittleEndian.Uint32(p[8:]), nil
}

func (x *x11Conn) changeProperty(mode byte, window, property, typ uint32, format byte, data []byte) error {
	body := binary.LittleEndian.AppendUint32(nil, window)
	body = binary.LittleEndian.AppendUint32(body, property)
	body = binary.LittleEndian.AppendUint32(body, typ)
	body = append(body, format, 0, 0, 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)/int(format/8)))
	body = append(body, data...)
	_, err := x.request(xChangeProperty, mode, body)
	return err
}

func (x *x11Conn) setSelectionOwner(owner, selection, time uint32) error {
	body := binary.LittleEndian.AppendUint32(nil, owner)
	body = binary.LittleEndian.AppendUint32(body, selection)
	body = binary.LittleEndian.AppendUint32(body, time)
	_, err := x.request(xSetSelectionOwner, 0, body)
	return err
}

func serveX11(ctx context.Context, value []byte, ready func()) error {
	x, err := dialX11()
	if err != nil {
		return unavailable("x11", err)
	}
	defer func() { _ = x.conn.Close() }()
	fail := func(err error) error { return unavailable("x11", err) }

	// ChangeProperty is the largest request sent: 24 bytes of header before
	// the data. A value too big for one request would need the INCR transfer
	// protocol, which a secret has no business needing.
	if limit := x.maxReq - 24; len(value) > limit {
		return fmt.Errorf("x11: value is %d bytes; the X11 clipboard takes at most %d without INCR", len(value), limit)
	}

	atoms := make(map[string]uint32)
	for _, name := range append([]string{"CLIPBOARD", "TARGETS", passwordHint}, textTypes...) {
		if name == "STRING" {
			atoms[name] = atomSTRING
			continue
		}
		a, err := x.internAtom(name)
		if err != nil {
			return fail(err)
		}
		atoms[name] = a
	}
	clipboard := atoms["CLIPBOARD"]

	// An input-only window: selections need an owner window, and nothing
	// ever maps it. PropertyChangeMask is only for the timestamp below.
	body := binary.LittleEndian.AppendUint32(nil, x.window)
	body = binary.LittleEndian.AppendUint32(body, x.root)
	body = binary.LittleEndian.AppendUint16(body, 0) // x
	body = binary.LittleEndian.AppendUint16(body, 0) // y
	body = binary.LittleEndian.AppendUint16(body, 1) // width
	body = binary.LittleEndian.AppendUint16(body, 1) // height
	body = binary.LittleEndian.AppendUint16(body, 0) // border
	body = binary.LittleEndian.AppendUint16(body, classInputOnly)
	body = binary.LittleEndian.AppendUint32(body, 0) // visual: from parent
	body = binary.LittleEndian.AppendUint32(body, cwEventMask)
	body = binary.LittleEndian.AppendUint32(body, propertyChangeMask)
	if _, err := x.request(xCreateWindow, 0, body); err != nil {
		return fail(err)
	}

	// ICCCM forbids CurrentTime for SetSelectionOwner. The standard way to
	// learn the server's clock is a zero-length append to a property on our
	// own window, which still produces a PropertyNotify carrying the time.
	if err := x.changeProperty(propModeAppend, x.window, atomWMName, atomSTRING, 8, nil); err != nil {
		return fail(err)
	}
	var ownTime uint32
	for ownTime == 0 {
		var p []byte
		if len(x.pending) > 0 {
			p, x.pending = x.pending[0], x.pending[1:]
		} else if p, err = x.packet(); err != nil {
			return fail(err)
		}
		switch p[0] & 0x7f {
		case xPropertyNotify:
			if binary.LittleEndian.Uint32(p[4:]) == x.window {
				ownTime = binary.LittleEndian.Uint32(p[12:])
			}
		case xError:
			return fail(fmt.Errorf("creating the owner window failed with X error %d", p[1]))
		}
	}

	if err := x.setSelectionOwner(x.window, clipboard, ownTime); err != nil {
		return fail(err)
	}
	seq, err := x.request(xGetSelectionOwner, 0, binary.LittleEndian.AppendUint32(nil, clipboard))
	if err != nil {
		return fail(err)
	}
	p, err := x.reply(seq)
	if err != nil {
		return fail(err)
	}
	if owner := binary.LittleEndian.Uint32(p[8:]); owner != x.window {
		return errors.New("x11: the server did not grant clipboard ownership")
	}
	ready()

	packets := make(chan []byte)
	failed := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			p, err := x.packet()
			if err != nil {
				failed <- err
				return
			}
			select {
			case packets <- p:
			case <-stop:
				return
			}
		}
	}()

	for _, p := range x.pending {
		if done, err := x.handle(p, value, atoms, ownTime); done || err != nil {
			return err
		}
	}
	x.pending = nil

	for {
		select {
		case <-ctx.Done():
			// Relinquishing takes CurrentTime; it cannot steal from a newer
			// owner, because the server ignores it for a selection we lost.
			_ = x.setSelectionOwner(0, clipboard, 0)
			return nil
		case err := <-failed:
			return fmt.Errorf("x11: %w", err)
		case p := <-packets:
			if done, err := x.handle(p, value, atoms, ownTime); done || err != nil {
				return err
			}
		}
	}
}

// handle answers one packet. done reports that ownership has ended.
func (x *x11Conn) handle(p, value []byte, atoms map[string]uint32, ownTime uint32) (done bool, err error) {
	clipboard := atoms["CLIPBOARD"]
	switch p[0] & 0x7f {
	case xSelectionClear:
		// time, owner window, then the selection that was lost.
		return binary.LittleEndian.Uint32(p[12:]) == clipboard, nil

	case xSelectionRequest:
		time := binary.LittleEndian.Uint32(p[4:])
		requestor := binary.LittleEndian.Uint32(p[12:])
		selection := binary.LittleEndian.Uint32(p[16:])
		target := binary.LittleEndian.Uint32(p[20:])
		property := binary.LittleEndian.Uint32(p[24:])
		if property == 0 {
			property = target // obsolete clients; ICCCM says to use the target
		}

		refused := selection != clipboard || (time != 0 && time < ownTime)
		if !refused {
			refused = !x.answer(requestor, property, target, value, atoms)
		}
		if refused {
			property = 0
		}

		// SendEvent: destination, event mask, then a SelectionNotify.
		body := binary.LittleEndian.AppendUint32(nil, requestor)
		body = binary.LittleEndian.AppendUint32(body, 0)
		body = append(body, xSelectionNotify, 0, 0, 0)
		body = binary.LittleEndian.AppendUint32(body, time)
		body = binary.LittleEndian.AppendUint32(body, requestor)
		body = binary.LittleEndian.AppendUint32(body, selection)
		body = binary.LittleEndian.AppendUint32(body, target)
		body = binary.LittleEndian.AppendUint32(body, property)
		body = append(body, make([]byte, 8)...)
		_, err := x.request(xSendEvent, 0, body)
		return false, err
	}
	// Errors land here too: a requestor that destroyed its window before the
	// property was written produces BadWindow, which is its problem, not ours.
	return false, nil
}

// answer writes the requested conversion onto the requestor's property, and
// reports whether the target was one this package offers.
func (x *x11Conn) answer(requestor, property, target uint32, value []byte, atoms map[string]uint32) bool {
	if target == atoms["TARGETS"] {
		list := binary.LittleEndian.AppendUint32(nil, atoms["TARGETS"])
		list = binary.LittleEndian.AppendUint32(list, atoms[passwordHint])
		for _, t := range textTypes {
			list = binary.LittleEndian.AppendUint32(list, atoms[t])
		}
		return x.changeProperty(propModeReplace, requestor, property, atomATOM, 32, list) == nil
	}
	for name, atom := range atoms {
		if atom != target {
			continue
		}
		data, ok := payload(value, name)
		if !ok {
			return false
		}
		typ := target
		if name == "TEXT" {
			typ = atoms["UTF8_STRING"] // TEXT asks the owner to pick; say which
		}
		return x.changeProperty(propModeReplace, requestor, property, typ, 8, data) == nil
	}
	return false
}
