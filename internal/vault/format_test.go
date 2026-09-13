package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"kleidos/internal/errs"
)

func TestRoundTrip(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set("DB_USER", "alice"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := v.Encode(&buf); err != nil {
		t.Fatal(err)
	}

	got, err := Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := got.Get("DB_USER"); !ok || s.Value != "alice" {
		t.Fatalf("DB_USER round trip: got %+v, ok=%v", s, ok)
	}
	if _, ok := got.Get("NOPE"); ok {
		t.Fatal("absent key reported present")
	}
	if !bytes.Equal(got.FPKey, v.FPKey) {
		t.Fatal("fpkey did not survive the round trip")
	}
}

func TestKeysSerializeSorted(t *testing.T) {
	v, _ := New()
	for _, k := range []string{"ZULU", "ALPHA", "MIKE"} {
		if err := v.Set(k, "x"); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := v.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Index(out, "ALPHA") > strings.Index(out, "MIKE") ||
		strings.Index(out, "MIKE") > strings.Index(out, "ZULU") {
		t.Fatalf("keys not sorted on serialize: %s", out)
	}
}

func TestDecodeRefusesUnknownVersion(t *testing.T) {
	blob := `{"version":2,"fpkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","secrets":{}}`
	_, err := Decode(strings.NewReader(blob))
	if err == nil {
		t.Fatal("expected refusal of version 2, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported vault version 2") {
		t.Fatalf("error should name the version, got: %v", err)
	}
}

func TestCheckKey(t *testing.T) {
	valid := []string{"A", "_", "DB_USER", "A1", "_X9_"}
	invalid := []string{"", "a", "1A", "DB-USER", "DB USER", "DB.USER", "Ä", "DB$"}
	for _, k := range valid {
		if err := CheckKey(k); err != nil {
			t.Errorf("CheckKey(%q) = %v, want nil", k, err)
		}
	}
	for _, k := range invalid {
		if err := CheckKey(k); err == nil {
			t.Errorf("CheckKey(%q) = nil, want error", k)
		}
	}
}

func TestSetRejectsNUL(t *testing.T) {
	v, _ := New()
	if err := v.Set("K", "a\x00b"); err == nil {
		t.Fatal("expected NUL rejection at the write path")
	}
	if _, ok := v.Get("K"); ok {
		t.Fatal("rejected value was stored anyway")
	}
}

func TestFingerprintIsKeyed(t *testing.T) {
	a, _ := New()
	b, _ := New()

	if got := a.Fingerprint("hunter2"); len(got) != 8 {
		t.Fatalf("fingerprint should be 8 hex chars, got %q", got)
	}
	if first, second := a.Fingerprint("hunter2"), a.Fingerprint("hunter2"); first != second {
		t.Fatal("fingerprint is not deterministic")
	}
	if a.Fingerprint("hunter2") == a.Fingerprint("hunter3") {
		t.Fatal("distinct values collided")
	}
	// The point of keying: the same value fingerprints differently under a
	// different fpkey, so the digest is meaningless without the vault.
	if a.Fingerprint("hunter2") == b.Fingerprint("hunter2") {
		t.Fatal("fingerprint is not keyed by fpkey")
	}
}

func TestMissingReportsEveryName(t *testing.T) {
	v, _ := New()
	if err := v.Set("PRESENT", "x"); err != nil {
		t.Fatal(err)
	}
	got := v.Missing([]string{"A", "PRESENT", "B"})
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("want [A B] in request order, got %v", got)
	}
}

func TestEmptyValuesAreRefused(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	err = v.Set("EMPTY", "")
	if !errors.Is(err, errs.ErrEmptyValue) {
		t.Fatalf("want ErrEmptyValue, got %v", err)
	}
	if !strings.Contains(err.Error(), "EMPTY") {
		t.Fatalf("error should name the key, got: %v", err)
	}
	// A refused write stores nothing, so present-and-empty is not a state the
	// vault can be in -- which is what lets a caller treat presence as usable.
	if _, ok := v.Get("EMPTY"); ok {
		t.Fatal("a refused write stored the key anyway")
	}
}
