# kleidos — design rationale and measured findings

Why the tool behaves the way it does, and what was actually measured rather than
reasoned. The [README](README.md) covers setup and use; nothing here is needed to
operate kleidos.

Measurements were taken on Arch Linux, kernel 7.1.11, ext4 on NVMe, Go 1.27.0,
`filippo.io/age v1.3.2`, dash 0.5.13.4 and bash 5.3, on 2026-09-02.

---

## What this protects against, and what it does not

**There is no boundary against an agent running as you.** Not a weak one — none.
Two reasons, and they compound:

1. **The identity has no passphrase, by choice.** It is usable by anything
   running as your user. That is what makes unattended operation work, and it is
   the whole reason there is no cryptographic boundary. These are the same fact
   stated twice.
2. **The permission matcher is bypassable.** Any path spelling other than the
   bare name slips past a rule written against that name. Measured, still true.

What the tool does buy, honestly stated:

- Secrets are not sitting in plaintext files on disk.
- Secrets are not in `argv`, so not in `/proc/<pid>/cmdline`, which is
  world-readable.
- Plaintext does not reach a transcript **by default** — getting it there takes a
  deliberate, differently-spelled command the permission layer can prompt on.
- One place to rotate from when something does leak.

That is accident prevention and blast-radius reduction. It is not confinement.
**Assume any secret an agent has handled may be in a transcript, and make
rotation cheap.** Rotation is the recovery path, and it is the only one.

The fix for the time-bound gap is a session lock — a passphrase-wrapped identity
with a cached unwrapped key and an absolute TTL. It is deferred deliberately,
because it costs unattended operation, which is the point of the tool in v1. It
is the only deferred item that would produce an actual boundary, and it is worth
promoting the moment unattended operation stops being the priority.

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

Under dash it is worse, for a second and independent reason — see the dash
finding below.

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

---

## Measured findings

### Write path under concurrency

50 concurrent writers x 20 runs on ext4: **50/50 keys kept every run, zero
leftover temp files.** `.bak` shares an inode with the pre-rename vault, and the
link count goes 1 → 2 → 1 across a save (the transient 2 is not observable from
outside the write; a shared inode implies it).

The broken-lock control — identical, but unlinking the lock after release — is
the reason to believe the lock is load-bearing rather than assume it:

| | reference machine | measured here |
|---|---|---|
| sound lock, 50 x 20 | 50/50 every run | same |
| broken lock | lost on **every one** of 20 runs, 36–64% | lost in **11 of 20** runs, worst run kept 22/50 |
| `link: file exists` TOCTOU under broken lock | observed | observed, 1–2 writers per losing run |

The broken variant loses less *often* here, but when it loses it loses just as
hard. The mechanism reproduces exactly; only the race window differs, which is
what a faster disk would predict. One consequence: because it fails on roughly
half of runs rather than all of them, the control needs the full 20 runs to be
trustworthy, so it skips under `-short` rather than reporting a false pass at two
runs.

The unlink-then-link in the `.bak` step is a TOCTOU that is only safe because the
lock is sound. Under the broken variant it surfaced as `link: file exists` —
those writers at least failed loudly, while the rest lost silently.

### `shellQuote`

18.0M fuzz executions in 90 seconds with no failures, plus a 20-case corpus
through dash and bash in three substitution modes, plus 2000 random values per
shell. The corpus includes: bare `'`, the sequence `'\''` as data, `"`, `$(id)`,
backtick `id`, `${HOME}`, lone backslash, literal `\n`, embedded newline,
trailing newlines, `!`, `#comment`, `--not-a-flag`, empty string, quote soup,
UTF-8, and 1000 bytes of random printable ASCII.

`/bin/sh` is bash on Arch, so the test suite resolves `dash` and `bash` by name
and fails if they turn out to be the same binary. A suite that ran `sh` and then
`bash` would test bash twice and report a false pass on the one function where
being wrong is arbitrary code execution.

### dash corrupts some high bytes through command substitution

Not a kleidos bug, and worth knowing independently:

```
dash -c 's=$(printf "a\302\202b"); printf %s "$s"'   ->  61 c2 81 82 62
bash, same command                                   ->  61 c2 82 62
```

dash injects `0x81` — its internal `CTLESC` marker — before `0x82`, `0x8b` and
`0x8e`. There is no `eval` and no quoting involved: assigning a command
substitution to a variable corrupts the value on its own.

Two consequences. `s=$(kleidos export); eval "$s"` is excluded from the supported
substitution modes. And it is a second, independent reason to prefer `reveal -0`
over `K=$(kleidos reveal FOO)`, arriving at the same conclusion as the
trailing-newline loss by a different route.

### Permission rules

Measured against the real binary with `reveal` temporarily set to `deny`, so
every outcome left an observable artifact. Properties of one Claude Code version
on one machine; worth re-running.

| Spelling | Result |
|---|---|
| `kleidos reveal FOO` | denied |
| `kleidos  reveal FOO` (extra whitespace) | denied |
| `echo hi && kleidos reveal FOO` | denied |
| `X=kleidos; $X reveal FOO` | denied |
| `env kleidos reveal FOO` | denied |
| `sh -c 'kleidos reveal FOO'` | blocked, but by the **classifier**, not the matcher |
| `./kleidos reveal FOO` | **runs** — bypass |
| `/abs/path/kleidos reveal FOO` | **runs** — bypass |

The matcher is more capable than a naive prefix comparison: it sees through
compound commands and variable indirection, and treats `env` as a pass-through
wrapper. Both path-spelling bypasses remain open.

**The `sh -c` row is the one to read carefully.** It was blocked, but the refusal
came from the auto-mode classifier — a separate, undocumented mechanism with
different coverage, which fires on how a command looks rather than on what it
does. Whether the matcher itself still has that hole is therefore undetermined.
Do not count the classifier: testing only alarming-looking commands will lead you
to conclude the rules are tighter than they are.

**`Read(/abs/path)` silently matches nothing.** The rule needs a doubled leading
slash. Written the obvious way it failed open and the identity file was readable
in full, secret key included; a single slash appears to be resolved relative to
the project directory. Rotating the identity was the fix, and it was cheap only
because the vault was still empty. This is the failure mode that matters most: a
rule that fails open is worse than no rule, because it is trusted.

**The `Read` deny rule extends to Bash on this version.** `sha256sum` against the
identity path was refused by the permission system, while the same command
against `recipients` in the same directory ran — so the block is path-specific
and attributable to the rule. That is stronger than assumed. It is still policy
rather than kernel enforcement: treat it as a courtesy, not a boundary.

**`ask` approvals do not persist within a session.** Two identical consecutive
invocations both prompted. This is not verifiable from inside a session — an
`ask` prompt leaves no artifact an agent can observe, so it took a human watching
the screen. Only denials are machine-checkable, which is why the table above was
measured with `deny` rules rather than `ask` rules.

**Rules added mid-session are inert until restart, and fail open with no
feedback.** Always restart after editing settings, and verify with a `deny` rule
that a denial is actually visible.

---

## Known limits

- **No boundary against an agent.** Enforcement is policy, the policy layer is
  bypassable at least two ways, and the identity has no passphrase.
- No time bound. The identity is usable by anything running as you, indefinitely.
- A single blob means mutations require decryption, so write-only-for-an-agent is
  not available.
- Plaintext exists as uncontrollable `string` copies during JSON decode.
- `run` guards its own stdout and argv, not the child's. `reveal` and `export`
  are explicit dumps.
- `K=$(kleidos reveal FOO)` is silently lossy. Use `-0`.
- Syncing the vault between machines can silently lose writes: single blob,
  last-write-wins.
- Permission matcher behavior is version-dependent, measured once, on one version,
  on one machine — and a `Read` rule written the obvious way protected nothing.
