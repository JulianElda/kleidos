# kleidos — implementation handoff

Self-contained. You do not need any prior artifact to build from this document.

Some claims below were measured rather than reasoned. Two markers distinguish them:

- **[measured]** — observed on the reference machine, and the mechanism behind it is portable (POSIX semantics, library internals, shell behavior). Treat as reliable.
- **[re-check]** — observed on the reference machine, but it is a property of *that* machine or *that* Claude Code version, not of anything permanent. **Verify before relying on it.** The re-check procedure is in "Provenance" below.

Everything unmarked is design reasoning. Argue with it freely.

## What this is

A CLI that manages key/value secrets in a single age-encrypted file. Primary caller is Claude Code, not a human, which drives most of the design decisions below.

**Target:** Arch / NixOS, single user, personal + work laptop. Go (for `filippo.io/age`).

The name is κλειδός, genitive of κλείς — "of the key," the same root behind *clavis* and *clavicle*. It is a personal tool, not an Anthropic product, despite being built for an Anthropic client; earlier drafts were named `claude-secrets` and that implication is the reason they aren't anymore. Nothing in the design depends on the name, so rename freely if something better turns up before v1 ships.

**Read the next section before anything else.** An earlier draft claimed the security boundary lived in Claude Code's permission rules. That claim was tested and is false. The design is still worth building; it is not worth building under a wrong belief about what it protects against.

## What this protects against, and what it does not

There is **no boundary against the agent in v1.** Not a weak one — none. Two independent reasons, and they compound:

1. **The identity has no passphrase, by choice.** It is always usable by anything running as the user. That is what makes unattended agent operation work, and it is the whole reason there is no cryptographic boundary. These are the same fact stated twice.
2. **Claude Code's permission matcher is bypassable** **[re-check]**. Two distinct classes: path spelling (`/abs/path/kleidos get FOO` and `./rel/path/kleidos get FOO` both execute) and shell nesting (`sh -c 'kleidos get FOO'` executes; the matcher sees `sh`).

What the tool does buy, honestly stated:

- Secrets are not sitting in plaintext files on disk.
- Secrets are not in `argv`, so not in `/proc/<pid>/cmdline`, which is world-readable.
- Plaintext does not reach a transcript **by default** — getting it there takes a deliberate, differently-spelled command the permission layer can prompt on.
- One place to rotate from when something does leak.

That is accident prevention and blast-radius reduction. It is not confinement. **Assume any secret the agent has handled may be in a transcript, and make rotation cheap** — rotation is the recovery path, and it is the only one.

The fix for the time-bound gap is the session lock (deferred item 3). It is deferred deliberately: it costs unattended operation, which is the point of the tool in v1.

## Provenance, and what to re-check

Measurements came from this environment:

| | |
|---|---|
| kernel | Linux 6.18 WSL2, x86_64 |
| distro | Arch Linux |
| Go | 1.27.0 |
| filesystem | ext4 (`/tmp` was tmpfs and deliberately avoided) |
| age library | `filippo.io/age v1.3.2` |
| shells | dash 0.5.13, bash 5.3 (note `/bin/sh` is bash on Arch — install dash to test both) |
| Claude Code | version not recorded; assume stale |

**Re-check these five before trusting the corresponding sections.** Each is one command:

```bash
# 1. /proc asymmetry — justifies `run`'s entire design
ls -l /proc/self/environ /proc/self/cmdline      # expect 0400 and 0444

# 2. ptrace hardening — the second layer under `run`
cat /proc/sys/kernel/yama/ptrace_scope           # 1 = restricted; 0 loses a layer

# 3. scratch filesystem — write-path durability tests are meaningless on tmpfs
stat -f -c %T /path/to/your/scratch              # must not be tmpfs

# 4. descriptor state under the harness — the `get` check depends on this
test -t 2 && echo TTY || echo NOTTY              # expect NOTTY under Claude Code
script -qc 'test -t 2 && echo TTY || echo NOTTY' /dev/null   # expect TTY
```

The fifth is the permission matcher, which needs its own procedure — see "Verifying the permission rules" below. It is the most important of the five and the most likely to have changed.

If any re-check disagrees with what this document says, **trust your machine and fix the document.** Note the disagreement rather than working around it silently.

## Storage

```
~/.local/share/kleidos/        (0700)
├── identity          AGE-SECRET-KEY-1...   (0600)
├── recipients        one age1... per line  (plaintext, readable)
├── lock              empty, never unlinked (0600)
└── secrets.age       the vault             (0600)
```

Respect `$XDG_DATA_HOME`. Nothing here may enter `/nix/store` — the identity stays imperative even if config later becomes declarative.

## Crypto

- **age via the Go library**, not by shelling out to the binary. Reason: plaintext stays in-process (so zeroing actually applies), typed errors instead of parsed stderr, single static binary.
- Native age identity (X25519). Not SSH keys — keeps the vault's key lifecycle independent of git/login keys.
- No passphrase. See "What this protects against"; this is the decision the threat model turns on.
- `recipients` supports multiple lines. Every write re-encrypts to all of them.

## Vault format

Single blob. Plaintext inside the age envelope:

```json
{
  "version": 1,
  "fpkey": "base64 of 32 random bytes",
  "secrets": {
    "DB_USER": { "value": "...", "updated": "2026-08-30T12:04:11Z" }
  }
}
```

- Refuse unrecognized `version` rather than guessing.
- Values are objects, not bare strings — lets metadata be added later without a breaking migration.
- Keys sorted on serialize. Names constrained to `[A-Z_][A-Z0-9_]*`.
- `fpkey` is generated once at vault creation and never changes. It keys the `list` fingerprints.
- All metadata inside the ciphertext. No plaintext index — key names leak plenty on their own. Consequence: `list` requires the identity. Accepted.
- `.env` is import/export only, never the internal format.

### NUL is rejected at write time

Values may not contain `0x00`. Reject in `set` and `import`, not downstream.

The obvious place to catch this is `export`, since a shell variable cannot hold a NUL. But `environ` entries are NUL-terminated C strings too, so a NUL-containing value also breaks `run`. Rejecting at the two write paths makes "no value contains NUL" an invariant every consumer can rely on, rather than a check each consumer must remember. Keep the check in `shellQuote` as a backstop — it returns `(string, error)`, not `string`, precisely so the failure mode is an error rather than silent truncation or a panic.

## Write path

Every mutation, including delete, is read-modify-write: decrypt → mutate map → re-encrypt whole blob → atomic replace.

**[measured]** — 20 runs × 50 concurrent writers on ext4, 50/50 every run, zero leftover temp files.

Exact sequence:

1. `flock(LOCK_EX)` on `lock` (a **separate** file, opened `O_CREAT|0600`). Not on `secrets.age` — the vault legitimately does not exist before the first `set`, so locking it races on creation. **Never unlink `lock`.** `flock` locks an inode, not a path; once one writer unlinks it, the next `O_CREAT` produces a fresh inode and the two hold exclusive locks on different objects, so neither excludes the other. **[measured]** — a variant that unlinked the lock after release lost data on *every one* of 20 runs, 36–64% of writes, worst run keeping 18 of 50.
2. Read and decrypt `secrets.age` (absent is fine on first write).
3. Mutate the map.
4. Create the temp file in the **same directory**, mode `0600`. **Register the deferred unlink immediately on creation**, before writing anything — a failure between here and step 6 otherwise leaves a full ciphertext copy behind. Stream through the age library's writer. Then, in this order: `Close()` the **age writer** (flushes the final chunk and MAC), `Sync()` the file, `Close()` the file. Syncing before closing the age writer fsyncs an incomplete ciphertext.
5. Stat `secrets.age`; if present, unlink `secrets.age.bak` (ENOENT fine) then `link(secrets.age, secrets.age.bak)`. Hardlink, not copy. **Skip the whole step when `secrets.age` is absent** — the first write has nothing to back up and `link` returns ENOENT (errno 2) **[measured]**. Stat first rather than branching on the errno.
6. `rename` temp over `secrets.age`. This replaces the directory entry without freeing the old inode while `.bak` references it, so the previous ciphertext survives. **[measured]** — `.bak` and the pre-rename vault share an inode; link count goes 1 → 2 → 1. The only gap is `.bak` briefly absent while `secrets.age` is fully intact, which is harmless. Never *move* the vault to `.bak` — that creates a window with neither.
7. `fsync` the **directory**, not just the temp file. Without this the rename may not be durable.
8. Release the lock.

Step 5's unlink-then-link is a TOCTOU that is only safe because the lock is sound. Under the broken-lock variant it surfaced as `link: file exists` **[measured]**; those writers at least failed loudly, while the rest lost silently.

**Reads deliberately take no lock.** `rename` is atomic, so a reader opens either the old inode or the new one, whole, and never a torn file. This is a decision, not an oversight — do not later "fix" it by acquiring the lock in `get`, which would serialize every read against every write for no correctness gain and would let a stuck writer block reads.

`age.Encrypt` streams; memory is O(64 KiB) regardless of payload **[measured]** — 512 MiB payload, peak RSS 1.55% of it. The library writes the header straight to `dst` and returns a `stream.EncryptWriter` holding exactly one chunk (`ChunkSize = 64 KiB` plus AEAD overhead). Streaming to the file handle is load-bearing, not cosmetic.

### Reference implementation of the write path

This was written and stress-tested against the sequence above. It is correct as far as the tests go; adapt it to the real vault struct (it uses a flat `map[string]string`).

```go
// withLock performs step 1 (acquire) and step 8 (release).
func withLock(dir string, fn func() error) error {
	lockPath := filepath.Join(dir, "lock")
	// Separate lock file, O_CREAT|0600, NEVER unlinked.
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		lf.Close()
		return err
	}
	err = fn()
	syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	lf.Close()
	return err
}

// load performs step 2: read + decrypt, tolerating absence.
func load(dir string, ident age.Identity) (map[string]string, error) {
	f, err := os.Open(filepath.Join(dir, "secrets.age"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil // absence is not an error
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, ident)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func doSet(dir string, ident *age.X25519Identity, k, v string) error {
	m, err := load(dir, ident)
	if err != nil {
		return err
	}
	m[k] = v // step 3

	secrets := filepath.Join(dir, "secrets.age")
	bak := secrets + ".bak"

	// Step 4. Deferred unlink registered immediately, before anything can fail.
	tmp, err := os.CreateTemp(dir, ".secrets-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w, err := age.Encrypt(tmp, ident.Recipient())
	if err != nil {
		tmp.Close()
		return err
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		tmp.Close()
		return err
	}
	if err := w.Close(); err != nil { // MUST precede Sync: flushes final chunk + MAC
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Step 5. Skip entirely when the vault does not yet exist.
	if _, err := os.Stat(secrets); err == nil {
		if err := os.Remove(bak); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Link(secrets, bak); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Step 6.
	if err := os.Rename(tmp.Name(), secrets); err != nil {
		return err
	}

	// Step 7: fsync the directory, not just the file.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
```

Two details that are easy to drop and were caught only by testing: `w.Close()` must precede `tmp.Sync()`, and the deferred `os.Remove` must be registered at creation time (after a successful rename it becomes a harmless ENOENT).

## Command surface

```
kleidos set KEY               # prompt on /dev/tty, echo off
kleidos set KEY --stdin
kleidos get KEY [KEY...]      # terminal only, no escape hatch
kleidos reveal KEY [KEY...]   # the plaintext dump
kleidos reveal -0 K1 K2       # NUL-delimited, request order
kleidos list                  # names, timestamps, fingerprints
kleidos delete KEY
kleidos rename OLD NEW        # refuses if NEW exists; --force to clobber
kleidos run --only K1,K2 -- cmd
kleidos export                # env format for eval
kleidos import .env
```

No positional value on `set` — argv is world-readable via `/proc/<pid>/cmdline`.

`rename` **refuses when NEW already exists**, exiting non-zero and naming the collision; `--force` overwrites. Silently clobbering a live credential is unrecoverable once `.bak` rolls over. Rename **preserves `updated`** — the value did not change, only its name, and resetting it destroys the one staleness signal available.

Dropped from v1: `--env-file` / `secrets://` references, `--prefix` / `--strip`, `edit`, audit log, shell completions, provider abstraction. All deferred, none blocking.

### Why `reveal` is a verb and not a flag

The permission matcher gates on the leading tokens of a command and **cannot see flags** **[re-check]** — `get FOO --reveal` and `get FOO` are indistinguishable to it, both matched by `get:*`. An earlier draft had `--reveal` as a flag and proposed gating `get` as `ask` wholesale to compensate.

That does not work, for a measured reason: **an `ask` approval does not persist within a session** **[re-check]** — two identical consecutive invocations both prompted. So `get` as `ask` prompts on every read, and the predictable response is that the user routes around it, with the path-spelling bypass sitting right there. A gate that is both porous and constantly annoying is worse than either problem alone.

Making the dangerous operation its own verb aligns the command surface with the grain of the enforcement mechanism. Ordinary reads never prompt; the plaintext dumps do. This does not fix the bypasses — nothing does — but it removes the standing incentive to go looking for them.

**If your re-check finds that approvals now persist**, this restructuring is still fine, but the argument for it weakens and a flag would become viable again. Note it either way.

## `get` and the terminal check

`get` prints plaintext **only when stderr is a terminal**, and otherwise refuses with exit 125. There is no flag that overrides this. The override is a different command: `reveal`.

**Check `isatty(2)`, not `isatty(1)`.** Under Claude Code all three standard descriptors are non-TTY **[re-check]**, so stderr is true exactly when a human terminal is present, independent of what stdout is doing. Gating on stderr means `get FOO > file` and `get FOO | pbcopy` work for a human at a terminal while capture still refuses — strictly better for the stated purpose than gating on stdout.

**Scope, precisely.** This stops accidents, not intent:

- An agent that wants the value runs `reveal`, or spells the path differently, or wraps in `sh -c`. All work.
- `script -qc`, `unbuffer`, or any pty allocation makes the check pass while output is still captured **[measured]**.

The property worth having is that plaintext never reaches a transcript *by default*, and that putting it there is a distinct, promptable act. That is the whole claim. Do not upgrade it in your head while implementing.

## Where enforcement sits, and how far it goes

Claude Code's permission rules, applied per verb:

```
Bash(kleidos set:*)      allow
Bash(kleidos get:*)      allow
Bash(kleidos list:*)     allow
Bash(kleidos delete:*)   allow
Bash(kleidos rename:*)   allow
Bash(kleidos import:*)   allow
Bash(kleidos run:*)      allow
Bash(kleidos reveal:*)   ask
Bash(kleidos export:*)   ask
Read(/home/<user>/.local/share/kleidos/identity)   deny
```

All findings in this section are **[re-check]** — they are properties of one Claude Code version on one machine.

**What the matcher caught:** bare invocation, appended flags, compound `&&` segments, variable indirection (`X=kleidos; $X get FOO`), `env` wrapping, extra whitespace. More capable than a naive prefix comparison — notably it treats `env` as a pass-through wrapper.

**What it did not catch:** any path spelling other than the bare name, absolute or relative; and `sh -c '...'`.

That combination makes the holes sharper rather than softer. They are not artifacts of a crude parser, which means they are unlikely to close by accident — but they may have closed on purpose since. Re-check.

There is a second, independent layer: an auto-mode classifier that blocked `sh -c "kleidos get FOO --reveal"` while the same command *without* the flag ran. Two enforcement layers with different coverage, and this design only reasons about one. **Do not count the classifier** — it is undocumented, it fired on the alarming-looking string rather than the operation, and in testing it masked a rule failure that only appeared once the flag was removed. If you test only obvious-looking commands you will conclude the rules are tighter than they are.

`run` stays `allow` because prompting on every ordinary command defeats the tool, and because `run` offers no guarantee a prompt would be protecting.

### Verifying the permission rules

Do this before writing any code, because two findings above may have changed and both affect the command surface.

1. **Rules added mid-session are inert until restart, and fail open with no feedback** **[re-check]**. This voided an entire test run during the original work. Always restart after editing settings.
2. **`ask` prompts leave no artifact an agent can observe.** Only denials appear in the transcript. So test with `deny` rules, not `ask` rules — that is what makes the behavior machine-checkable. Confirmed equivalent on at least one case where the same command prompted under `ask` and was denied under `deny`.
3. **No shell state persists between Claude Code tool calls** — no `export PATH=…`, no `cd`, no functions. Each case must be its own invocation, and prefixing `PATH=… cmd` changes the command string, which is the thing under test. Install the stub somewhere already on `PATH`.

Procedure: put a stub script named `kleidos` on `PATH` that echoes its arguments, set `get` and `export` to `deny`, restart, then run each of these as a separate invocation and record which are denied:

```
kleidos list                                  # expect: runs
kleidos get FOO                               # expect: denied
kleidos get FOO --reveal                      # expect: denied (by get:*, not the flag)
kleidos  get FOO                              # two spaces — expect: denied
echo hi && kleidos get FOO                    # expect: denied
X=kleidos; $X get FOO                         # expect: denied
env kleidos get FOO                           # expect: denied
sh -c 'kleidos get FOO'                       # expect: RUNS — the bypass
./path/to/kleidos get FOO                     # expect: RUNS — the bypass
/abs/path/to/kleidos get FOO                  # expect: RUNS — the bypass
```

Keep the alarming flag *off* the `sh -c` case. With `--reveal` attached, the classifier blocks it and you will wrongly conclude the rule caught it.

Then check persistence separately under real `ask` rules: run the same command twice and see whether the second prompts.

**Delete the stub when finished.** A script named `kleidos` on `PATH` will shadow the real binary once it exists, and it is a genuinely confusing failure to debug.

## `run`

```
kleidos run --only DB_USER,DB_PASSWORD -- psql -h localhost
```

- `--` is required; error clearly if absent rather than guessing.
- Decrypt once → build child env → **`execve`**, don't fork-and-wait. Gives correct signal handling and exit-code propagation for free.
- Values land in `environ` (`0400`, owner-only) not `argv` (`0444`). That asymmetry is the entire point — re-check both modes on your machine, since a `hidepid` mount or unusual hardening changes the picture.
- Fails before exec if decryption fails, so the command never runs with a blank credential.
- Secrets-win on env collisions, but warn on stderr when shadowing.
- Inject the minimum: children inherit everything, and so do grandchildren.

A second layer may be present: `ptrace_scope=1` **[re-check]** means a process can only be traced by its own ancestors, closing the ptrace route to another process's memory for non-descendants. Cite it in user docs only if your machine has it — a distro shipping `ptrace_scope=0` silently loses it.

**What `run` guarantees, precisely.** kleidos never writes the value to its own stdout and never places it in argv. After `execve` it has no control over anything. A child that prints its environment leaks, and `run --only K -- sh -c 'echo $K'` is a deliberate read — equivalent in intent to `reveal`, just spelled differently. No tool-side check prevents this. Do not attempt to block shell interpreters: `env sh`, `make`, and any wrapper defeat a name-based check while breaking legitimate use.

The value `run` retains is the common case where the child is a real program that does not echo its environment. That is worth having; it is not a guarantee about output.

**Masking (deferred).** The alternative that catches accidental echo: fork-and-wait instead of exec, scan child stdout/stderr for exact secret values, substitute the fingerprint. Precedent: GitHub Actions. Costs — loses free signal handling and exit-code propagation, breaks interactive children without a pty, defeated by any transformation (base64, `jq`, printing a substring), and the scan buffer itself holds plaintext. Not in v1.

## `export`

```
eval "$(kleidos export)"
```

Command substitution makes stdout a pipe unconditionally, including when a human types it, so no terminal check can apply — it would make `export` unusable for its only purpose. `export` is a deliberate plaintext dump, gated as its own verb in the permission layer, which is the only place the gate can live.

**Quoting is a shell injection surface, not a formatting detail.** Output is `eval`-ed, so a bug here is arbitrary code execution.

- Wrap every value in single quotes.
- Escape each embedded single quote as `'\''` (close, escaped literal quote, reopen). This is the only sequence that survives, and it handles newlines and `$` for free since single quotes suppress all expansion.
- Emit `export KEY='...'` and nothing else. No double quotes, no `printf %q` (locale- and shell-dependent).

**[measured]** — byte-identical round trips across 18 corpus cases × 4 substitution modes × dash and bash, plus five minutes of coverage-guided fuzzing (~1.2M target invocations, no failures). Corpus included: bare `'`, the sequence `'\''` as data, `"`, `$(id)`, backtick `id`, `${HOME}`, lone backslash, literal `\n`, embedded newline, trailing newlines, `!`, `#comment`, `--not-a-flag`, empty string, quote soup, and 1000 bytes of random printable ASCII.

Reference implementation:

```go
// ErrNUL is returned for values a shell variable cannot hold.
var ErrNUL = errors.New("value contains NUL byte; cannot be exported to a shell variable")

// shellQuote wraps v in single quotes, escaping embedded single quotes as '\''.
func shellQuote(v []byte) (string, error) {
	if bytes.IndexByte(v, 0) >= 0 {
		return "", ErrNUL
	}
	var sb strings.Builder
	sb.Grow(len(v) + 2)
	sb.WriteByte('\'')
	for _, c := range v {
		if c == '\'' {
			sb.WriteString(`'\''`) // close, escaped literal quote, reopen
		} else {
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('\'')
	return sb.String(), nil
}
```

The `(string, error)` signature is deliberate. As `func([]byte) string` the only options on a NUL would have been silent truncation or panic.

**Validate key names at emit time**, against `[A-Z_][A-Z0-9_]*`, not just on import. The left-hand side of an `eval`-ed assignment is its own injection point, and trusting the blob assumes every past write enforced the constraint. Fail the whole `export` on a bad name rather than skipping the entry.

Trailing newlines survive `eval "$(kleidos export)"` intact in both shells **[measured]** — the value's newlines sit inside the quotes, and substitution only strips the trailing newlines of the whole emitted line. The stripping problem belongs to `reveal`, below.

## `reveal`

The explicit plaintext dump. No terminal check; the gate is the permission rule on the verb.

**Trailing newlines are destroyed by `K=$(kleidos reveal FOO)`** **[measured]** — `a\n` and `a\n\n\n` both come back as `a`, in dash and bash alike. This is command substitution, not something the tool can fix.

So document `-0` as *the* machine-readable path rather than a niche flag: `reveal -0 K1 K2` emits NUL-delimited values in request order, and NUL is guaranteed absent from values by the write-time rejection. Anything reading a value into a shell variable via `$(...)` is silently lossy for values with trailing whitespace, and certificate and key material is exactly the category that has it.

## `list`

The fingerprint is `HMAC-SHA256(fpkey, value)` truncated to 8 hex characters.

Not a plain hash. `list` runs freely and needs no approval, so a bare digest turns it into a confirmation oracle: any low-entropy secret — a PIN, a short passphrase, a value from a known set — falls to trivial offline brute force. Keying with `fpkey` makes the digest meaningless to anyone who cannot already decrypt the vault, which is the correct property: fingerprints exist to confirm two machines hold the same value, or that a write landed.

If that feels like more machinery than it earns, dropping fingerprints from v1 is defensible — `updated` already answers "did my write land."

## `import`

Accept a **strict subset** of `.env` and reject everything else loudly, with a line number. A silently mis-parsed value stored as a secret is discovered at the worst possible moment.

Accepted:

- `KEY=value`, optionally prefixed `export `.
- Blank lines.
- `#` comments **on their own line only**. Not trailing — `PASS=hunter2 # prod` has no correct reading, and guessing produces either a wrong value or a wrong comment.
- Values optionally wrapped in matching single or double quotes, stripped on read. **No expansion is ever performed**, in either quote style — no `$VAR`, no `\n` unescaping, no command substitution. A `.env` file is data, not a script.
- Keys must match `[A-Z_][A-Z0-9_]*`.

Rejected as errors, not warnings: multi-line values, line continuations, unmatched quotes, duplicate keys within the file, values containing NUL, anything else.

**Collision policy: refuse by default.** If any key in the file already exists in the vault, import nothing, exit non-zero, and list every colliding name. `--overwrite` replaces them; `--skip-existing` keeps the vault's version. All-or-nothing either way — a half-applied import leaves the vault in a state nobody chose.

## Error handling

| Code | Meaning |
|---|---|
| 0 | success |
| 120 | generic |
| 121 | key not found |
| 122 | vault not found |
| 123 | identity missing/unreadable |
| 124 | decryption failed |
| 125 | `get` refused: no terminal on stderr |

**Own codes live at 120–125, deliberately high.** 1–7 collides maximally with real programs: `psql` returns 3, `git` returns 1/2/128, `curl` uses 1 through 92. `run -- psql` returning 3 would be ambiguous between "key not found" and "psql could not connect," which is exactly the confusion the table exists to prevent. With this layout, **any code below 120 came from the child, unmodified**, and every code from 120 up is ours.

126, 127, and 128+n are shell conventions and stay reserved. `run` follows them: **127** when the command does not exist, **126** when it exists but is not executable.

This leaves no headroom above 125. New error classes either subdivide an existing code with a clear stderr message or fall back to 120 — do not creep into 126/127.

Multi-key `get` and `reveal` are all-or-nothing: if any key is missing, fail non-zero and list **every** missing name. Returning a username with an empty password is the dangerous outcome. Distinguish "key absent" from "key present, value empty".

## Go-specific notes

**`[]byte` at the edges, not end to end.** The rule cannot be honored through the vault format: `encoding/json` unmarshals `"value": "..."` into a `string`, and the decoder buffers the entire plaintext internally regardless of target type. Honoring it across decode needs a custom unmarshaler over `json.RawMessage`, which is real cost for a benefit the GC can undo anyway.

So scope it and stop:

- Keep `[]byte` where the code controls the buffer: `term.ReadPassword` output, the `--stdin` read, `reveal` writes, child env construction, the `set` path before serialize.
- Accept that decode produces uncontrollable `string` copies.
- Do not half-implement the stricter rule. A `[]byte` discipline abandoned partway gives the appearance of a guarantee with none of the substance.

Other notes:

- Zeroing is best-effort: the GC may have moved the data. Do it where cheap, don't contort the design.
- `RLIMIT_CORE` to 0 — buys more than zeroing does, costs one syscall.
- Restore terminal state on `SIGINT` during the `set` prompt. A `^C` leaving echo off is an easy bug to ship.
- Flush and check the write error on `reveal` output. A silently truncated secret is worse than none.
- `golang.org/x/term` for `ReadPassword` and `IsTerminal`.

## Testing notes

- **Write-path tests must run on the real filesystem, not `/tmp`,** if `/tmp` is tmpfs — `fsync` there succeeds without doing anything, so steps 4 and 7 are unverifiable. The race half of a concurrency test stays valid; the durability half becomes theatre. Check with `stat -f -c %T`.
- **The concurrency test is 50 parallel writers × 20 runs, counting keys afterward.** One green run proves nothing; it is a race. Also assert zero leftover temp files.
- **Test the broken-lock variant deliberately** — unlink the lock after release and confirm the count drops. If it does not drop on your filesystem, that is worth knowing rather than assuming.
- **Fuzz `shellQuote` against real `sh` and `bash`,** and confirm they are actually different binaries. On Arch, `/bin/sh` is bash; without installing dash you test bash twice and report a false pass.
- **Assert permission behavior with `deny` rules, not `ask` rules,** per the procedure above. Never treat "the matcher will prompt" as verifiable from inside a session.
- Keep pty tests to single-purpose commands. Spawning a pty *and* inspecting `/proc/self/fd` in one compound command reads as sandbox probing and gets blocked by the classifier.

## Setup the user must do first

```bash
age-keygen -o ~/.local/share/kleidos/identity
chmod 600 ~/.local/share/kleidos/identity
chmod 700 ~/.local/share/kleidos
age-keygen -y ~/.local/share/kleidos/identity \
  > ~/.local/share/kleidos/recipients
```

**Then, before storing anything real:** generate a second identity as a break-glass backup, add its public key as a second line in `recipients`, and keep the private half off the machine (USB stick, printed, password manager). A recipient can only be added while the vault can still be decrypted — lose the only identity and everything is unrecoverable. The same mechanism covers the two-machine case: each machine keeps its own identity, both recipients in the file, nothing sensitive travels between them.

**Then add the permission rules, restart Claude Code, and verify.** Rules added mid-session are inert until restart and fail open with no feedback. Someone who adds vault rules and keeps working believes they are protected and is not. A gate that fails open silently is worse than no gate, because it is trusted.

Verification: temporarily set `reveal` to `deny` instead of `ask`, restart, run `kleidos reveal ANY_KEY`, confirm a visible denial, set it back, restart again. Anything less than a visible denial means the rules are not loaded.

Write the absolute path in the `Read` deny rule, not `~`. It is per-tool policy, not kernel enforcement — Bash reaches the same bytes.

## Known limits, stated deliberately

- **No boundary against the agent.** Enforcement is policy, the policy layer is bypassable at least two ways, and the identity has no passphrase. Rotation is the recovery path.
- No time bound in v1. The identity is usable by anything running as the user, indefinitely.
- Single blob means mutations require decryption, so write-only-for-Claude isn't available.
- Plaintext exists as uncontrollable `string` copies during JSON decode. Zeroing covers the edges only.
- `run` guards its own stdout and argv, not the child's. `reveal` and `export` are explicit dumps.
- `K=$(kleidos reveal FOO)` silently eats trailing newlines. Use `-0`.
- Permission matcher behavior is version-dependent and was measured once, on one version, on one machine.
- Sync between machines can silently lose writes — single blob, last-write-wins. Don't assume sync gives multi-machine writes.

## Deferred, in rough priority order

1. Audit log (append-only; log which provider resolved once providers exist).
2. `edit` verb via `$XDG_RUNTIME_DIR` temp file — note editor swap/undo files as a footgun.
3. Session lock: passphrase-wrapped identity (`age -p`) + unwrapped key cached in `$XDG_RUNTIME_DIR` with absolute TTL, `unlock`/`lock` verbs. **The only item here that produces an actual boundary**, and it costs unattended operation to get it. Promote it the moment unattended operation stops being the priority.
4. Provider abstraction — `resolve() → age identity`, config-ordered, **never** silently falling through from "configured but locked" to a weaker source. KeePassXC via Secret Service is the intended first provider.
5. Prod tier: separate vault encrypted to an `age-plugin-yubikey` recipient. Requires shelling out to `age` for plugin stanzas, so keep the encrypt/decrypt call site swappable.
