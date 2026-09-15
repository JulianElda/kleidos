package clipboard

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

const (
	fakeRoot       = 0x100
	fakeServerTime = 1000
	fakeRequestor  = 0x4000001
)

// fakeXServer is just enough of an X server to drive the client: setup,
// atoms, the property round trip that yields a timestamp, and selection
// ownership. Everything the client does to other windows is reported on
// channels for the test to assert on.
type fakeXServer struct {
	t      *testing.T
	conn   net.Conn
	maxReq uint16 // in 4-byte words

	atoms  map[string]uint32
	window uint32

	owners chan [3]uint32 // SetSelectionOwner: owner, selection, time
	props  chan xProperty // ChangeProperty on any window but the client's
	sent   chan []byte    // the 32-byte event of each SendEvent
}

type xProperty struct {
	window, property, typ uint32
	format                byte
	data                  []byte
}

// startXServer listens on a fresh socket and points DISPLAY at it, unsetting
// WAYLAND_DISPLAY and XAUTHORITY so nothing reaches the real session.
func startXServer(t *testing.T, maxReq uint16) *fakeXServer {
	t.Helper()
	dir := t.TempDir()
	l, err := net.Listen("unix", filepath.Join(dir, "X99"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	old := x11SocketDir
	x11SocketDir = dir
	t.Cleanup(func() { x11SocketDir = old })
	t.Setenv("DISPLAY", ":99")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XAUTHORITY", filepath.Join(dir, "absent"))

	f := &fakeXServer{
		t:      t,
		maxReq: maxReq,
		atoms:  map[string]uint32{"STRING": atomSTRING},
		owners: make(chan [3]uint32, 8),
		props:  make(chan xProperty, 8),
		sent:   make(chan []byte, 8),
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		f.conn = conn
		defer func() { _ = conn.Close() }()
		f.loop()
	}()
	return f
}

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func (f *fakeXServer) loop() {
	head := make([]byte, 12)
	if _, err := io.ReadFull(f.conn, head); err != nil {
		return
	}
	auth := make([]byte, (int(u16(head[6:]))+3)&^3+(int(u16(head[8:]))+3)&^3)
	if _, err := io.ReadFull(f.conn, auth); err != nil {
		return
	}

	vendor := []byte("fake")
	body := binary.LittleEndian.AppendUint32(nil, 0)        // release
	body = binary.LittleEndian.AppendUint32(body, 0x200000) // resource id base
	body = binary.LittleEndian.AppendUint32(body, 0x1fffff) // resource id mask
	body = binary.LittleEndian.AppendUint32(body, 0)        // motion buffer
	body = binary.LittleEndian.AppendUint16(body, uint16(len(vendor)))
	body = binary.LittleEndian.AppendUint16(body, f.maxReq)
	body = append(body, 1, 0, 0, 0, 0, 0, 0, 0) // one screen, no formats
	body = append(body, 0, 0, 0, 0)
	body = append(body, vendor...)
	screen := make([]byte, 40)
	binary.LittleEndian.PutUint32(screen, fakeRoot)
	body = append(body, screen...)
	reply := []byte{1, 0, 11, 0, 0, 0}
	reply = binary.LittleEndian.AppendUint16(reply, uint16(len(body)/4))
	_, _ = f.conn.Write(append(reply, body...))

	var seq uint16
	var owner uint32
	nextAtom := uint32(100)
	for {
		h := make([]byte, 4)
		if _, err := io.ReadFull(f.conn, h); err != nil {
			return
		}
		req := make([]byte, 4*int(u16(h[2:]))-4)
		if _, err := io.ReadFull(f.conn, req); err != nil {
			return
		}
		seq++

		switch h[0] {
		case xInternAtom:
			name := string(req[4 : 4+u16(req)])
			if _, ok := f.atoms[name]; !ok {
				f.atoms[name] = nextAtom
				nextAtom++
			}
			_, _ = f.conn.Write(f.packet(xReply, seq, 8, f.atoms[name]))
		case xCreateWindow:
			f.window = u32(req)
		case xChangeProperty:
			p := xProperty{u32(req), u32(req[4:]), u32(req[8:]), req[12], nil}
			n := int(u32(req[16:])) * int(p.format/8)
			p.data = req[20 : 20+n]
			if p.window == f.window {
				// The client's timestamp probe.
				_, _ = f.conn.Write(f.packet(xPropertyNotify, seq, 4, p.window, p.property, fakeServerTime))
				continue
			}
			f.props <- p
		case xSetSelectionOwner:
			owner = u32(req)
			f.owners <- [3]uint32{owner, u32(req[4:]), u32(req[8:])}
		case xGetSelectionOwner:
			_, _ = f.conn.Write(f.packet(xReply, seq, 8, owner))
		case xSendEvent:
			f.sent <- req[8:40]
		}
	}
}

// packet builds a 32-byte reply or event: code, sequence, then words from
// offset.
func (f *fakeXServer) packet(code byte, seq uint16, offset int, words ...uint32) []byte {
	p := make([]byte, 32)
	p[0] = code
	binary.LittleEndian.PutUint16(p[2:], seq)
	for i, w := range words {
		binary.LittleEndian.PutUint32(p[offset+4*i:], w)
	}
	return p
}

// owned waits for the client to take the clipboard, and returns the owner
// window and the CLIPBOARD atom as the client used them.
func (f *fakeXServer) owned() (window, clipboard uint32, time uint32) {
	f.t.Helper()
	select {
	case o := <-f.owners:
		return o[0], o[1], o[2]
	case <-deadline():
		f.t.Fatal("the client never took the selection")
		return
	}
}

// request sends a SelectionRequest for target, as a pasting client would
// cause, and returns the property written (if any) and the SelectionNotify.
func (f *fakeXServer) request(target string) (*xProperty, []byte) {
	f.t.Helper()
	const property = 0x300
	_, _ = f.conn.Write(f.packet(xSelectionRequest, 0, 4,
		fakeServerTime+1, f.window, fakeRequestor, f.atoms["CLIPBOARD"], f.atoms[target], property))

	var prop *xProperty
	for {
		select {
		case p := <-f.props:
			prop = &p
		case ev := <-f.sent:
			return prop, ev
		case <-deadline():
			f.t.Fatalf("no SelectionNotify for %s", target)
		}
	}
}

func deadline() <-chan time.Time { return time.After(5 * time.Second) }

func TestX11TakesOwnershipWithAServerTimestamp(t *testing.T) {
	f := startXServer(t, 0xffff)
	serve(t, []byte("hunter2"))

	window, selection, ts := f.owned()
	if window != f.window || selection != f.atoms["CLIPBOARD"] {
		t.Fatalf("owner %#x of %d, want %#x of CLIPBOARD", window, selection, f.window)
	}
	// ICCCM: CurrentTime (0) makes later requests impossible to order.
	if ts != fakeServerTime {
		t.Fatalf("took ownership at time %d, want the server's %d", ts, fakeServerTime)
	}
}

func TestX11PastesAreByteExact(t *testing.T) {
	f := startXServer(t, 0xffff)
	value := []byte("line one\nline two\n\n")
	serve(t, value)
	f.owned()

	for _, target := range []string{"UTF8_STRING", "STRING", "text/plain;charset=utf-8"} {
		prop, ev := f.request(target)
		if prop == nil || !bytes.Equal(prop.data, value) || prop.format != 8 {
			t.Errorf("%s: property %+v, want the value in format 8", target, prop)
			continue
		}
		if prop.window != fakeRequestor || prop.typ != f.atoms[target] {
			t.Errorf("%s: written to %#x as type %d", target, prop.window, prop.typ)
		}
		if ev[0] != xSelectionNotify || u32(ev[20:]) != prop.property {
			t.Errorf("%s: notify %v does not name the written property", target, ev)
		}
	}
}

// TEXT asks the owner to choose an encoding; the reply has to say which.
func TestX11AnswersTextAsUTF8String(t *testing.T) {
	f := startXServer(t, 0xffff)
	serve(t, []byte("hunter2"))
	f.owned()

	prop, _ := f.request("TEXT")
	if prop == nil || prop.typ != f.atoms["UTF8_STRING"] {
		t.Fatalf("TEXT answered as %+v, want type UTF8_STRING", prop)
	}
}

func TestX11TargetsIncludeThePasswordHint(t *testing.T) {
	f := startXServer(t, 0xffff)
	serve(t, []byte("hunter2"))
	f.owned()

	prop, _ := f.request("TARGETS")
	if prop == nil || prop.typ != atomATOM || prop.format != 32 {
		t.Fatalf("TARGETS answered as %+v", prop)
	}
	var hint bool
	for i := 0; i+4 <= len(prop.data); i += 4 {
		hint = hint || u32(prop.data[i:]) == f.atoms[passwordHint]
	}
	if !hint {
		t.Fatal("TARGETS does not list the password hint")
	}
	if prop, _ := f.request(passwordHint); prop == nil || string(prop.data) != passwordHintPayload {
		t.Fatalf("hint answered as %+v", prop)
	}
}

func TestX11RefusesATargetItDidNotOffer(t *testing.T) {
	f := startXServer(t, 0xffff)
	serve(t, []byte("hunter2"))
	f.owned()
	f.atoms["image/png"] = 999

	prop, ev := f.request("image/png")
	if prop != nil {
		t.Fatalf("wrote %+v for an unoffered target", prop)
	}
	if u32(ev[20:]) != 0 {
		t.Fatal("a refusal must name no property")
	}
}

// SelectionClear carries the owner window before the selection atom. Reading
// the wrong one of the two left the server running after being replaced.
func TestX11StopsWhenSomethingElseIsCopied(t *testing.T) {
	f := startXServer(t, 0xffff)
	_, done := serve(t, []byte("hunter2"))
	f.owned()

	_, _ = f.conn.Write(f.packet(xSelectionClear, 0, 4, fakeServerTime+1, f.window, f.atoms["CLIPBOARD"]))
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestX11RelinquishesAtTheDeadline(t *testing.T) {
	f := startXServer(t, 0xffff)
	cancel, done := serve(t, []byte("hunter2"))
	f.owned()

	cancel()
	window, selection, _ := f.owned()
	if window != 0 || selection != f.atoms["CLIPBOARD"] {
		t.Fatalf("at the deadline: owner %#x of %d, want None of CLIPBOARD", window, selection)
	}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

// One ChangeProperty carries the whole value; past that, it would need INCR.
// The refusal has to come before ownership, not at paste time.
func TestX11RefusesAValueTooLargeForOneRequest(t *testing.T) {
	startXServer(t, 64) // 256 bytes
	called := false
	err := Serve(context.Background(), bytes.Repeat([]byte("a"), 300), func() { called = true })
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("want a size error, got %v", err)
	}
	if called {
		t.Fatal("ready was called for a value that cannot be served")
	}
}

func TestX11AcceptsOnlyLocalDisplays(t *testing.T) {
	for display, want := range map[string]string{
		":0":           "0",
		":1.0":         "1",
		"unix:12":      "12",
		"":             "",
		"host:0":       "",
		"10.0.0.1:0.0": "",
		":":            "",
		":x":           "",
	} {
		t.Setenv("DISPLAY", display)
		got, err := x11Display()
		if (err == nil) != (want != "") || got != want {
			t.Errorf("DISPLAY=%q: got %q, %v; want %q", display, got, err, want)
		}
	}
}

func TestXauthCookieMatchesTheLocalDisplay(t *testing.T) {
	entry := func(family uint16, addr, num, name, data string) []byte {
		b := binary.BigEndian.AppendUint16(nil, family)
		for _, f := range []string{addr, num, name, data} {
			b = binary.BigEndian.AppendUint16(b, uint16(len(f)))
			b = append(b, f...)
		}
		return b
	}
	file := bytes.Join([][]byte{
		entry(256, "otherhost", "0", "MIT-MAGIC-COOKIE-1", "wrong-host"),
		entry(256, "myhost", "1", "MIT-MAGIC-COOKIE-1", "wrong-display"),
		entry(256, "myhost", "0", "XDM-AUTHORIZATION-1", "wrong-scheme"),
		entry(256, "myhost", "0", "MIT-MAGIC-COOKIE-1", "right"),
	}, nil)

	name, data := xauthCookie(bytes.NewReader(file), "myhost", "0")
	if name != "MIT-MAGIC-COOKIE-1" || string(data) != "right" {
		t.Fatalf("got %q %q", name, data)
	}
	if _, data := xauthCookie(bytes.NewReader(file), "myhost", "7"); data != nil {
		t.Fatalf("matched display 7: %q", data)
	}
}
