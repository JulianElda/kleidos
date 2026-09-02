package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, body string) ([]entry, error) {
	t.Helper()
	return parseDotenv(strings.NewReader(body))
}

func TestDotenvAcceptedForms(t *testing.T) {
	body := strings.Join([]string{
		"# a comment on its own line",
		"",
		"   ",
		"PLAIN=value",
		"export EXPORTED=value",
		"  INDENTED=value",
		`SINGLE='single quoted'`,
		`DOUBLE="double quoted"`,
		"EMPTY=",
		`EMPTY_QUOTED=""`,
		`NO_EXPANSION="$HOME and $(id) and ${X}"`,
		`LITERAL_BACKSLASH_N="a\nb"`,
		`HASH_IN_QUOTES="#fff"`,
		`SPACES_IN_QUOTES="  padded  "`,
	}, "\n")

	entries, err := parse(t, body)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"PLAIN":               "value",
		"EXPORTED":            "value",
		"INDENTED":            "value",
		"SINGLE":              "single quoted",
		"DOUBLE":              "double quoted",
		"EMPTY":               "",
		"EMPTY_QUOTED":        "",
		"NO_EXPANSION":        `$HOME and $(id) and ${X}`,
		"LITERAL_BACKSLASH_N": `a\nb`,
		"HASH_IN_QUOTES":      "#fff",
		"SPACES_IN_QUOTES":    "  padded  ",
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		w, ok := want[e.key]
		if !ok {
			t.Errorf("unexpected key %s", e.key)
			continue
		}
		if e.value != w {
			t.Errorf("%s = %q, want %q", e.key, e.value, w)
		}
	}
}

func TestDotenvRejections(t *testing.T) {
	cases := []struct{ name, body, wants string }{
		{"trailing comment", "PASS=hunter2 # prod", "#"},
		{"trailing comment no space", "PASS=hunter2#prod", "#"},
		{"line continuation", "A=one\\\nB=two", "continuation"},
		{"unmatched single quote", "A='unterminated", "unmatched"},
		{"unmatched double quote", `A="unterminated`, "unmatched"},
		{"text after closing quote", `A="value" trailing`, "after the closing quote"},
		{"lowercase key", "key=value", "invalid key name"},
		{"digit-leading key", "1KEY=value", "invalid key name"},
		{"dashed key", "A-B=value", "invalid key name"},
		{"space before equals", "A =value", "spaces"},
		{"no assignment", "JUST_A_WORD", "not a KEY=value"},
		{"duplicate key", "A=1\nA=2", "duplicate key A"},
		{"NUL in value", "A=x\x00y", "NUL"},
		{"interior carriage return", "A=va\rlue", "carriage return"},
		{"doubled carriage return", "A=value\r\r", "carriage return"},
		{"unquoted trailing space", "A=value ", "whitespace"},
		{"unquoted internal quote", `A=va'lue`, "quote character"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse(t, c.body)
			if err == nil {
				t.Fatalf("%q was accepted", c.body)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("error should mention %q, got: %v", c.wants, err)
			}
			// Every rejection names the line, so the file can be fixed.
			if !strings.Contains(err.Error(), "line ") {
				t.Fatalf("error should name the line, got: %v", err)
			}
		})
	}
}

// Ordinary CRLF files parse cleanly: bufio.ScanLines drops the carriage return
// before the parser sees it.
func TestDotenvAcceptsCRLFFiles(t *testing.T) {
	entries, err := parse(t, "A=1\r\nB=\"two\"\r\n")
	if err != nil {
		t.Fatalf("a CRLF file should parse: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	for _, e := range entries {
		if strings.Contains(e.value, "\r") {
			t.Errorf("%s kept a carriage return: %q", e.key, e.value)
		}
	}
	if entries[0].value != "1" || entries[1].value != "two" {
		t.Fatalf("values = %q, %q", entries[0].value, entries[1].value)
	}
}

func TestDotenvReportsTheRightLineNumber(t *testing.T) {
	_, err := parse(t, "# comment\n\nA=1\nB=bad # trailing\n")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("want line 4, got: %v", err)
	}
}

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportLoadsFile(t *testing.T) {
	dir := vaultDir(t)
	path := writeEnv(t, "A=1\nexport B=\"two\"\n")

	if err := Import([]string{path}); err != nil {
		t.Fatal(err)
	}
	if got := value(t, dir, "A"); got != "1" {
		t.Fatalf("A = %q", got)
	}
	if got := value(t, dir, "B"); got != "two" {
		t.Fatalf("B = %q", got)
	}
}

func TestImportRefusesCollisionsAndChangesNothing(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "EXISTING_A", "keep-a"); err != nil {
		t.Fatal(err)
	}
	if err := setStdin(t, "EXISTING_B", "keep-b"); err != nil {
		t.Fatal(err)
	}
	path := writeEnv(t, "EXISTING_A=new-a\nFRESH=new\nEXISTING_B=new-b\n")

	err := Import([]string{path})
	if err == nil {
		t.Fatal("import over existing keys was allowed")
	}
	// Every colliding name is listed, not just the first.
	for _, name := range []string{"EXISTING_A", "EXISTING_B"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should name %s, got: %v", name, err)
		}
	}

	// All or nothing: the non-colliding key must not have landed either.
	v := read(t, dir)
	if _, ok := v.Get("FRESH"); ok {
		t.Fatal("a refused import applied part of the file")
	}
	if got, _ := v.Get("EXISTING_A"); got.Value != "keep-a" {
		t.Fatalf("EXISTING_A = %q, want keep-a", got.Value)
	}
}

func TestImportOverwrite(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "EXISTING", "old"); err != nil {
		t.Fatal(err)
	}
	path := writeEnv(t, "EXISTING=new\nFRESH=also-new\n")

	if err := Import([]string{path, "--overwrite"}); err != nil {
		t.Fatal(err)
	}
	if got := value(t, dir, "EXISTING"); got != "new" {
		t.Fatalf("EXISTING = %q, want new", got)
	}
	if got := value(t, dir, "FRESH"); got != "also-new" {
		t.Fatalf("FRESH = %q", got)
	}
}

func TestImportSkipExisting(t *testing.T) {
	dir := vaultDir(t)
	if err := setStdin(t, "EXISTING", "old"); err != nil {
		t.Fatal(err)
	}
	path := writeEnv(t, "EXISTING=new\nFRESH=also-new\n")

	if err := Import([]string{"--skip-existing", path}); err != nil {
		t.Fatal(err)
	}
	if got := value(t, dir, "EXISTING"); got != "old" {
		t.Fatalf("EXISTING = %q, want old", got)
	}
	if got := value(t, dir, "FRESH"); got != "also-new" {
		t.Fatalf("FRESH = %q", got)
	}
}

func TestImportRejectsBothPolicyFlags(t *testing.T) {
	vaultDir(t)
	path := writeEnv(t, "A=1\n")
	if err := Import([]string{"--overwrite", "--skip-existing", path}); err == nil {
		t.Fatal("mutually exclusive flags were accepted")
	}
}

// A malformed file must not create or touch the vault at all.
func TestImportRejectsBeforeTouchingTheVault(t *testing.T) {
	dir := vaultDir(t)
	path := writeEnv(t, "GOOD=1\nBAD=value # trailing\n")

	if err := Import([]string{path}); err == nil {
		t.Fatal("malformed file was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.age")); !os.IsNotExist(err) {
		t.Fatalf("a rejected import created the vault: %v", err)
	}
}

func TestImportEmptyFile(t *testing.T) {
	vaultDir(t)
	path := writeEnv(t, "# nothing but a comment\n\n")
	if err := Import([]string{path}); err == nil {
		t.Fatal("an empty file was accepted silently")
	}
}

func TestImportMissingFile(t *testing.T) {
	vaultDir(t)
	if err := Import([]string{"/nonexistent/.env"}); err == nil {
		t.Fatal("a missing file was accepted")
	}
}
