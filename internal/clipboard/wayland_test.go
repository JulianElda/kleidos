package clipboard

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeCompositor is just enough of a Wayland compositor to drive the client:
// it advertises globals, tracks the objects the client creates, and records
// what the client offers. Events are framed with the client's own encoder --
// the wire format is the same in both directions.
type fakeCompositor struct {
	t       *testing.T
	w       *wlConn
	objects map[uint32]string // client object id -> interface or role
	offers  []string
	// selections receives each set_selection argument: a source id, or 0.
	// Receiving from it is also what makes w, source and offers safe for the
	// test goroutine to read: the fake sets all three before sending.
	selections chan uint32
	source     uint32
	device     uint32
}

// startCompositor listens on a fresh socket, points WAYLAND_DISPLAY at it and
// unsets DISPLAY, so nothing reaches the real session. globals are the
// interfaces to advertise.
func startCompositor(t *testing.T, globals ...string) *fakeCompositor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wayland-test")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	t.Setenv("WAYLAND_DISPLAY", path)
	t.Setenv("DISPLAY", "")

	f := &fakeCompositor{
		t:          t,
		objects:    map[uint32]string{wlDisplayID: "wl_display"},
		selections: make(chan uint32, 8),
	}
	accepted := make(chan struct{})
	go func() {
		conn, err := l.AcceptUnix()
		if err != nil {
			return
		}
		f.w = &wlConn{conn: conn}
		close(accepted)
		f.loop(globals)
	}()
	t.Cleanup(func() {
		select {
		case <-accepted:
			_ = f.w.conn.Close()
		default:
		}
	})
	return f
}

func (f *fakeCompositor) loop(globals []string) {
	for {
		req, err := f.w.next(0)
		if err != nil {
			return
		}
		a := wlArgs(req.body)
		switch iface := f.objects[req.obj]; {
		case iface == "wl_display" && req.op == displayGetRegistry:
			registry := a.uint()
			f.objects[registry] = "wl_registry"
			for i, g := range globals {
				_ = f.w.request(registry, registryGlobal, uint32(i+1), g, uint32(1))
			}
		case iface == "wl_display" && req.op == displaySync:
			_ = f.w.request(a.uint(), callbackDone, uint32(0))
		case iface == "wl_registry" && req.op == registryBind:
			_, name, _, id := a.uint(), a.string(), a.uint(), a.uint()
			f.objects[id] = name
		case (iface == dataControlManagers[0] || iface == dataControlManagers[1]) && req.op == managerCreateSource:
			f.source = a.uint()
			f.objects[f.source] = "source"
		case (iface == dataControlManagers[0] || iface == dataControlManagers[1]) && req.op == managerGetDevice:
			f.device = a.uint()
			f.objects[f.device] = "device"
		case iface == "source" && req.op == sourceOffer:
			f.offers = append(f.offers, a.string())
		case iface == "device" && req.op == deviceSetSelection:
			f.selections <- a.uint()
		}
	}
}

// paste asks the client for typ the way a pasting application would, through
// the compositor, and returns what came back.
func (f *fakeCompositor) paste(typ string) []byte {
	f.t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	body := binary.NativeEndian.AppendUint32(nil, uint32(len(typ)+1))
	body = pad4(append(append(body, typ...), 0))
	msg := binary.NativeEndian.AppendUint32(nil, f.source)
	msg = binary.NativeEndian.AppendUint32(msg, uint32(8+len(body))<<16|sourceSend)
	msg = append(msg, body...)
	_, _, err = f.w.conn.WriteMsgUnix(msg, syscall.UnixRights(int(w.Fd())), nil)
	_ = w.Close() // the client holds its own copy now
	if err != nil {
		f.t.Fatal(err)
	}

	_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(r)
	if err != nil {
		f.t.Fatalf("pasting %s: %v", typ, err)
	}
	return got
}

// serve runs Serve in the background and returns once ready has been called.
func serve(t *testing.T, value []byte) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, value, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Serve returned before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve never became ready")
	}
	return cancel, done
}

func wait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

func TestWaylandPastesAreByteExact(t *testing.T) {
	f := startCompositor(t, "wl_seat", "ext_data_control_manager_v1")
	value := []byte("line one\nline two\n\n")
	serve(t, value)

	if sel := <-f.selections; sel != f.source {
		t.Fatalf("set_selection(%d), want the source %d", sel, f.source)
	}
	for _, typ := range []string{"text/plain;charset=utf-8", "UTF8_STRING", "TEXT"} {
		if got := f.paste(typ); string(got) != string(value) {
			t.Errorf("paste %s = %q, want %q", typ, got, value)
		}
	}
}

// The hint is what keeps the value out of clipboard managers' history. It has
// to be offered, and offered first, and its payload is fixed by convention.
func TestWaylandOffersThePasswordHintFirst(t *testing.T) {
	f := startCompositor(t, "wl_seat", "ext_data_control_manager_v1")
	serve(t, []byte("hunter2"))
	<-f.selections

	if len(f.offers) == 0 || f.offers[0] != passwordHint {
		t.Fatalf("offers = %q, want %s first", f.offers, passwordHint)
	}
	if got := f.paste(passwordHint); string(got) != passwordHintPayload {
		t.Fatalf("hint payload = %q, want %q", got, passwordHintPayload)
	}
}

func TestWaylandSendsNothingForATypeItDidNotOffer(t *testing.T) {
	f := startCompositor(t, "wl_seat", "ext_data_control_manager_v1")
	serve(t, []byte("hunter2"))
	<-f.selections

	if got := f.paste("image/png"); len(got) != 0 {
		t.Fatalf("paste image/png = %q, want nothing", got)
	}
}

func TestWaylandSpeaksTheWlrootsProtocolToo(t *testing.T) {
	f := startCompositor(t, "wl_seat", "zwlr_data_control_manager_v1")
	serve(t, []byte("hunter2"))
	<-f.selections

	if got := f.paste("text/plain"); string(got) != "hunter2" {
		t.Fatalf("paste = %q", got)
	}
}

func TestWaylandClearsTheSelectionAtTheDeadline(t *testing.T) {
	f := startCompositor(t, "wl_seat", "ext_data_control_manager_v1")
	cancel, done := serve(t, []byte("hunter2"))
	<-f.selections

	cancel()
	select {
	case sel := <-f.selections:
		if sel != 0 {
			t.Fatalf("set_selection(%d) at the deadline, want null", sel)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the selection was not cleared at the deadline")
	}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

// Another copy ends the job early, and without clearing: the clipboard holds
// someone else's value by then.
func TestWaylandStopsWhenSomethingElseIsCopied(t *testing.T) {
	f := startCompositor(t, "wl_seat", "ext_data_control_manager_v1")
	_, done := serve(t, []byte("hunter2"))
	<-f.selections

	_ = f.w.request(f.source, sourceCancelled)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	select {
	case sel := <-f.selections:
		t.Fatalf("set_selection(%d) after losing ownership", sel)
	default:
	}
}

// A compositor without data-control is not a failed copy: Serve moves on to
// X11, and with no DISPLAY either, reports that no clipboard was usable.
func TestWaylandWithoutDataControlFallsThrough(t *testing.T) {
	startCompositor(t, "wl_seat")
	called := false
	err := Serve(context.Background(), []byte("hunter2"), func() { called = true })
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if called {
		t.Fatal("ready was called without a clipboard")
	}
}

func TestServeRefusesAnEmptyValue(t *testing.T) {
	startCompositor(t, "wl_seat", "ext_data_control_manager_v1")
	if err := Serve(context.Background(), nil, func() { t.Fatal("ready called") }); err == nil {
		t.Fatal("an empty value was served")
	}
}
