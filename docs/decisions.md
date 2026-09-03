# Design decisions

Why the tool is shaped the way it is. Nothing here is needed to operate kleidos;
it exists so a decision is not re-litigated or "fixed" without knowing what it
cost. The enforceable subset of these is listed as invariants in `CLAUDE.md`.

Target: Arch / NixOS, single user, personal and work laptop. Go, for
`filippo.io/age` as a library.

---

## Command surface

### Why `get` checks `isatty(2)` and not `isatty(1)`

Under an agent harness all three standard descriptors are non-TTY, so stderr is a
terminal exactly when a human one is present, independent of what stdout is
doing. Gating on stderr means `get FOO > file` and `get FOO | pbcopy` work for a
human at a terminal while a captured invocation still refuses — strictly better
for the stated purpose than gating on stdout.

**This stops accidents, not intent.** An agent that wants the value runs
`reveal`, spells the path differently, or allocates a pty; all work, and
`script -qc` makes the check pass while output is still captured. The property
worth having is that plaintext does not reach a transcript *by default*, and that
putting it there is a distinct, promptable act. That is the whole claim.

### Why `reveal` is a verb and not a flag

The permission matcher gates on the leading tokens of a command and cannot see
flags, so `get FOO --reveal` and `get FOO` are indistinguishable to it. The
alternative was gating `get` as `ask` wholesale.

That does not work, for a measured reason: **`ask` approvals do not persist
within a session** — two identical consecutive invocations both prompted. So
`get` as `ask` prompts on every read, and the predictable response is that the
user routes around it, with the path-spelling bypass sitting right there. A gate
that is both porous and constantly annoying is worse than either problem alone.

Making the dangerous operation its own verb aligns the command surface with the
grain of the enforcement mechanism. Ordinary reads never prompt; the plaintext
dumps do. This fixes no bypass — nothing does — but it removes the standing
incentive to go looking for them.

### Why `reveal -0` is the machine-readable path, not a niche flag

`K=$(kleidos reveal FOO)` destroys trailing newlines: `a\n` and `a\n\n\n` both
come back as `a`, in dash and bash alike. That is command substitution, not
something the tool can fix, and certificate and key material is exactly the
category that has trailing whitespace.

Under dash it is worse, for a second and independent reason — see
[findings.md](findings.md#dash-corrupts-some-high-bytes-through-command-substitution).

NUL is a safe delimiter precisely because the write paths reject it.

### Why NUL is rejected at write time

The obvious place to catch a NUL is `export`, since a shell variable cannot hold
one. But `environ` entries are NUL-terminated C strings too, so a NUL-containing
value also breaks `run`. Rejecting at the two write paths — `set` and `import` —
makes "no value contains NUL" an invariant every consumer can rely on, rather
than a check each consumer must remember.

`shellQuote` keeps the check as a backstop, and returns `(string, error)` rather
than `string` precisely so the failure mode is an error rather than silent
truncation or a panic.

### Why `export` quoting is a security surface

The output is `eval`-ed, so a bug there is arbitrary code execution. Single
quotes suppress every form of expansion, which handles `$`, backticks, newlines
and backslashes for free; the only byte needing treatment is the single quote
itself, and `'\''` — close, escaped literal quote, reopen — is the only sequence
that survives. Deliberately not `printf %q`, which is locale- and
shell-dependent.

Key names are re-validated at emit time, not just on import: the left-hand side
of an `eval`-ed assignment is its own injection point, and trusting the stored
blob assumes every past write enforced the constraint. A bad name fails the whole
export rather than skipping the entry, because a silently short export is how a
caller ends up running with a missing credential.

There is no terminal check on `export` and there cannot be one: command
substitution makes stdout a pipe unconditionally, including when a human types
it, so any such check would make the command useless for its only purpose.

### Why `run` requires `--only`, and what it does not guarantee

Children inherit the whole environment, and so do grandchildren. An
inject-everything default would violate the principle the flag exists to serve,
so `--only` is required rather than optional.

`execve` rather than fork-and-wait gives correct signal handling and exit-code
propagation for free, and leaves no parent process holding plaintext. Decryption
failure stops the command before it starts, so it never runs with a blank
credential.

**What `run` guarantees, precisely:** kleidos never writes the value to its own
stdout and never places it in argv. After `execve` it has no control over
anything. A child that prints its environment leaks, and
`run --only K -- sh -c 'echo $K'` is a deliberate read, equivalent in intent to
`reveal`, just spelled differently. No tool-side check prevents this, and a
name-based check on shell interpreters would break legitimate use while being
defeated by `env`, `make`, or any wrapper.

The value `run` retains is the common case where the child is a real program that
does not echo its environment. That is worth having; it is not a guarantee about
output.

Masking — fork-and-wait, scan child output for exact secret values, substitute a
fingerprint, as GitHub Actions does — was considered and deferred. It loses free
signal handling and exit-code propagation, breaks interactive children without a
pty, is defeated by any transformation (base64, `jq`, printing a substring), and
the scan buffer itself holds plaintext.

### Why `import` is strict

A silently mis-parsed value stored as a secret is discovered at the worst
possible moment. Every rejection names a line so the file can be fixed.

Trailing comments are refused because `PASS=hunter2 # prod` has no correct
reading, and guessing produces either a wrong value or a wrong comment. Unquoted
values containing `#`, quotes, or leading/trailing whitespace are refused for the
same reason; quoting is the fix in every case. No expansion is performed in
either quote style, because a `.env` file is data, not a script.

Collisions refuse by default and list every colliding name. `--overwrite` and
`--skip-existing` are all-or-nothing, because a half-applied import leaves the
vault in a state nobody chose.

### Why fingerprints are keyed

`list` runs freely and needs no approval, so a bare digest would turn it into a
confirmation oracle: any low-entropy secret — a PIN, a short passphrase, a value
from a known set — falls to trivial offline brute force. Keying with a secret
stored inside the vault (`fpkey`) makes the digest meaningless to anyone who
cannot already decrypt it, which is the correct property. Fingerprints exist to
confirm that two machines hold the same value, or that a write landed.

### Why the exit codes start at 120

| Code | Meaning |
|---|---|
| 0 | success |
| 120 | generic |
| 121 | key not found |
| 122 | vault not found |
| 123 | identity missing or unreadable |
| 124 | decryption failed |
| 125 | `get` refused: stderr is not a terminal |
| 126 | `run`: command found but not executable |
| 127 | `run`: command not found |

The range 1–7 collides maximally with real programs: `psql` returns 3, `git`
returns 1/2/128, `curl` uses 1 through 92. Since `run` execs a child whose status
passes through unmodified, `run -- psql` returning 3 would be ambiguous between
"key not found" and "psql could not connect" — exactly the confusion the table
exists to prevent.

With codes at 120 and above, **any code below 120 came from the child,
unmodified**. 126, 127 and 128+n stay reserved for the shell conventions. This
leaves no headroom above 125: new error classes either subdivide an existing code
with a clear stderr message or fall back to 120.

---

## The write path

Every mutation, including delete, is a read-modify-write: decrypt, mutate the
map, re-encrypt the whole blob, replace atomically.

Details that are easy to get wrong, each of which was caught by testing:

- **The lock is a separate file, and is never unlinked.** Separate, because the
  vault legitimately does not exist before the first `set`, so locking it races
  on creation. Never unlinked, because `flock` locks an inode rather than a path:
  once one writer unlinks the lock, the next `O_CREAT` produces a fresh inode,
  and two writers then hold exclusive locks on different objects and exclude
  nobody.
- **`w.Close()` must precede `tmp.Sync()`.** Closing the age writer flushes the
  final chunk and the MAC; syncing first fsyncs an incomplete ciphertext.
- **The deferred unlink is registered at temp-file creation**, before anything is
  written. A failure between creation and the rename would otherwise leave a full
  ciphertext copy behind. After a successful rename it is a harmless ENOENT.
- **`.bak` is a hardlink, and the step is skipped on the first write.** `link`
  returns ENOENT when the vault does not exist yet, so the code stats first
  rather than branching on the errno. The rename then replaces the directory
  entry without freeing the old inode while `.bak` still references it, so the
  previous ciphertext survives. Never *move* the vault to `.bak` — that creates a
  window with neither.
- **fsync the directory, not just the temp file.** Without it the rename may not
  be durable.
- **Reads take no lock.** `rename` is atomic, so a reader opens either the old
  inode or the new one, whole, and never a torn file. This is a decision, not an
  oversight: locking reads would serialize every read against every write for no
  correctness gain, and would let a stuck writer block reads.

`age.Encrypt` streams, so memory stays O(64 KiB) regardless of payload size.
Streaming to the file handle is load-bearing, not cosmetic.

### `[]byte` discipline stops at the edges

The rule cannot be honored end to end: `encoding/json` unmarshals into a `string`
and buffers the entire plaintext internally regardless of target type. Honoring
it across decode would need a custom unmarshaler over `json.RawMessage`, which is
real cost for a benefit the garbage collector can undo anyway.

So it is scoped deliberately: `[]byte` where the code controls the buffer — the
`--stdin` read, terminal input, child env construction — and uncontrollable
`string` copies accepted during decode. A `[]byte` discipline abandoned partway
gives the appearance of a guarantee with none of the substance.

Zeroing is best-effort for the same reason. `RLIMIT_CORE` set to 0 buys more than
zeroing does and costs one syscall.
