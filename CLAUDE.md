# kleidos — working notes for Claude Code

Key/value secrets in one age-encrypted file. Go; `filippo.io/age` is a library,
so nothing shells out to `age` at runtime — `age-keygen` appears only in setup.
Linux only: `flock`, `statfs`, `/dev/tty`, `/proc`.

**The primary caller is an agent, not a human.** That is why values never appear
in `argv`, why plaintext dumps are separate verbs, and why error taxonomy and
exit codes are load-bearing rather than cosmetic.

## Documents

Root holds only `README.md` (usage, no references to anything) and this file.
Everything else is in `docs/`:

| File | Holds | Write here when |
|---|---|---|
| [docs/threat-model.md](docs/threat-model.md) | what the tool protects against and what it does not; where enforcement sits; known limits | the security story changes |
| [docs/decisions.md](docs/decisions.md) | why the design is shaped this way, one section per decision, plus the write path | you make a non-obvious choice |
| [docs/findings.md](docs/findings.md) | measured results and the environment they came from | you measure something |
| [docs/verifying.md](docs/verifying.md) | the re-check procedures, including the permission-matcher method | a procedure changes |
| [docs/roadmap.md](docs/roadmap.md) | v1 non-goals and deferred items in priority order | scope moves |

**Read `docs/threat-model.md` first.** There is no boundary against an agent
running as the user, and an early draft of the design claimed otherwise.

The README carries examples and constraints only — no rationale, no gotcha
paragraphs, and no links to these files. Rationale goes in `docs/decisions.md`,
measurements in `docs/findings.md`. Do not move prose back into the README.

A finding is only as good as its environment: if you add one, add or confirm the
provenance table at the top of `docs/findings.md` in the same edit.

## Layout

```
main.go                 usage text, verb dispatch, RLIMIT_CORE(0), os.Exit
main_test.go            the built binary, driven as a process
internal/errs/          error sentinels, Coded, Code() -> exit status
internal/vault/
  paths.go              Dir(): $KLEIDOS_DIR, else $XDG_DATA_HOME/kleidos,
                        else ~/.local/share/kleidos
  format.go             Vault/Secret JSON, CheckKey, CheckValue, Fingerprint
  store.go              age envelope, flock, the atomic write path
internal/cmd/
  cmd.go                openStore, parseFlags, errHelp
  read.go               lookup (all-or-nothing), lookupSome (--optional),
                        emit, emitNUL, stdout seam
  <verb>.go             one file per verb, each with a `<verb>Usage` const
  dotenv.go             the strict .env subset parser (used only by import)
  nullrec.go            the NUL-delimited KEY=value parser (--null), same
  shellquote.go         single-quote escaping for export
internal/testenv/       scratch dirs and key material, shared by both suites
```

Dependencies point one way: `cmd` -> `vault` -> `errs`. `vault` must not import
`cmd`.

## Invariants

Breaking any of these silently is worse than any bug they look like. Each was a
deliberate decision, most of them tested directly.

- **No secret in `argv`, ever.** `/proc/<pid>/cmdline` is world-readable. `set`
  has no positional value argument; `run` puts values in the child's `environ`.
- **NUL and the empty string are rejected at write time** (`set`, `import`), so
  every consumer may assume a stored value is real and NUL-free. `run` re-checks
  both, and `shellQuote` re-checks NUL, only as a backstop against a vault
  written by something else — including a kleidos older than the empty rule. Do
  not relax the write-time checks. Empty is refused because "present but
  unusable" is a state no caller can distinguish from a working one, and it is
  what loops a consumer that re-execs itself on a missing credential.
- **`export` deliberately does *not* refuse a stored empty value**, and emits
  `K=''`. It is all-or-nothing over the whole vault, so failing it over one
  legacy key would make every other secret unreachable through that verb.
- **Multi-key reads are all-or-nothing.** `lookup` fails on any miss and names
  every absent key. A username with an empty password is the dangerous outcome.
  `run --optional` is the one exception, and only over keys the caller named
  there: absence is not an error for those, but an empty value still is.
- **Absence is a distinct state, and the only one `Vault.Get`'s bool has to
  carry.** Never collapse it to a zero value. "Present and empty" is no longer
  reachable through the write paths; `--optional` and `has` exist because
  absence, unlike emptiness, is legitimate.
- **`has` reports storage, `run` reports usability.** On a vault written before
  the empty rule the two disagree about an empty key, deliberately. `has` prints
  nothing on stdout — that is what keeps it plaintext-free and approval-free.
- **The `list` table is human output; `list --names` is the contract.** Programs
  read `--names`. Columns in the table may change.
- **`CheckKey` runs at export time too**, not only on write. The left-hand side
  of an `eval`ed assignment is its own injection point.
- **Reads take no lock.** `rename` is atomic, so a reader gets the old inode or
  the new one, whole. Locking reads would serialize them against writes for no
  correctness gain. This is not an oversight to fix.
- **The lock file is never unlinked.** `flock` locks an inode, not a path;
  unlink it and two writers hold exclusive locks on different objects.
- **`get` gates on stderr, not stdout.** Under an agent harness all three
  descriptors are non-TTY, so stderr is a terminal exactly when a human is. This
  keeps `get K > file` working while a captured call refuses.
- **Exit codes stay at 120+.** Anything below 120 came from a `run` child,
  unmodified. 126/127 follow the shell conventions. The table is in
  [docs/decisions.md](docs/decisions.md#why-the-exit-codes-start-at-120).
- **`[]byte` discipline stops at the edges.** `encoding/json` makes
  uncontrollable `string` copies; `zero()` in `set.go` is best-effort and
  labelled as such. Do not add zeroing that implies a guarantee it cannot give.
- **`shellQuote` is a code-execution surface.** Single quotes with `'\''` for an
  embedded quote, nothing else. Not `%q`, which is shell- and locale-dependent.
- Nothing in the vault directory may enter `/nix/store`.

## Adding a verb

1. `internal/cmd/<verb>.go`: a `<verb>Usage` const and
   `func Verb(args []string) error`.
2. Parse with `parseFlags(name, usage, args, bind)` — it allows flags after
   positionals (`kleidos set KEY --stdin`) and treats everything after `--` as
   positional. `run` hand-rolls its own parsing because `--` separates the
   child's argv; follow that only if you have the same problem.
3. Reads: `lookup(keys)`. Writes: `store.Update(func(*vault.Vault) error)`,
   which holds the lock for the whole read-modify-write.
4. Return `errs.Err*` sentinels (wrapped with `%w`) so `errs.Code` resolves the
   exit status; use `errs.Codef` for an explicit one.
5. Write to the package-level `stdout`, not `os.Stdout`.
6. Register in `main.go`'s switch and in both usage texts (`main.go`, README).
7. If it prints plaintext, it needs its own line in the README permission
   snippet, under `ask` rather than `allow`.

Steps 6 and 7 are checked: `main_test.go` reads the verbs back out of
`kleidos help` and fails if one is undispatchable or missing from the README's
permission snippet. It cannot tell `allow` from `ask` — that judgement is
still yours.

## Tests

```bash
go test ./...              # full suite; 20x50-writer write-path stress
go test -short ./...       # stress drops to 2 runs, broken-lock control skips
go test ./internal/cmd/ -run '^$' -fuzz FuzzShellQuote -fuzztime 60s
gofmt -l . && go vet ./...
golangci-lint run          # .golangci.yml; v2 config
```

Deliberately ignored errors are written `_ = f()`, not left bare: errcheck
enforces it, and it separates a decision from an oversight. A `//nolint` must
name its linter and give a reason.

Two environment requirements the suite checks rather than assumes, and fails
loudly on:

- **Scratch must not be tmpfs.** `fsync` there is a no-op, which makes
  write-path durability untestable. Default `~/.cache/kleidos-test`; override
  with `KLEIDOS_TEST_SCRATCH`. `t.TempDir()` is unusable for write-path tests.
- **`dash` and `bash` must both exist and be different binaries.** `/bin/sh` is
  bash on Arch, so `shells()` resolves both by name and fails rather than
  claiming two-shell coverage it does not have.

`KLEIDOS_DIR` is how tests reach a scratch vault; `cmd`'s `vaultDir(t)` sets it
via `t.Setenv`, and `main_test.go` passes it to the child. Never run a test that
could touch the real vault.

`main_test.go` builds the binary and drives it as a process. It is deliberately
thin: it covers only what stops being true when the seams below it are
substituted — the exit status reaching `os.Exit`, `run` actually calling
`execve` (the child reads its own `/proc/<pid>/cmdline` and `environ`), the
child inheriting `RLIMIT_CORE(0)`, and `get` against a real pty on stderr with
stdout still a pipe. A case that can be written against a function belongs in
the package suites instead.

Seams to use instead of refactoring for testability — all already in place:

| Seam | File | For |
|---|---|---|
| `stdout` | `cmd/read.go` | capturing verb output |
| `isTerminal` | `cmd/get.go` | forcing the TTY branch |
| `execve` | `cmd/run.go` | observing what would have been exec'd |
| `now` | `vault/format.go` | pinning timestamps |
| `withStdin(t, data)` | `cmd/helper_test.go` | `--stdin` paths |
| `(*Store).brokenUpdate` | `vault/stress_test.go` | the lock's negative control |
| `seedRaw(t, dir, k, v)` | `cmd/helper_test.go` | states the write paths refuse |

`TestBrokenLockActuallyLoses` is a control, not a feature test: it asserts the
unlocked variant *does* lose writes, and fails if it does not. Should it start
failing, the concurrency test above it is passing for the wrong reason — do not
delete either one.

Test names state the property, not the method
(`TestGetRefusesWithoutTerminalOnStderr`, `TestReadsAreNeverTorn`). Keep that.

## Conventions

- Single-line conventional-commit titles, no body apart from the attribution
  trailers Claude Code appends. Branch is `master`.
- Comments explain *why*, and are dense where a decision is non-obvious. Match
  the surrounding density rather than trimming it.
- Usage text lives in a `<verb>Usage` const beside the verb and doubles as its
  documentation.
- No new dependencies without a reason that survives "can the stdlib do this".
