# kleidos v1 — implementation plan

Derived from `kleidos-handoff.md`. That document is the specification; this one is
the build order. Where they disagree, the handoff wins.

## Settled decisions

| | |
|---|---|
| module path | `kleidos` (bare, no VCS prefix) |
| branch | `feat/v1`, one commit per stage |
| fingerprints | **in v1.** `fpkey` is generated at vault creation regardless — omitting the field is the only choice that is expensive to reverse |
| commit style | single-line conventional commit titles |

## Ordering principle

Build what everything else depends on first, and stand up the test harnesses for
the two genuinely dangerous things — the write path and `shellQuote` — before
piling verbs on top. Stages 1–5 are a chain. Stages 6–8 are leaves that depend
only on the core and may be reordered.

---

## Stage 1 — Skeleton

`go.mod`, package layout, verb dispatch with every command stubbed, exit-code
constants (120–125, with 126/127 reserved for `run`), and the error taxonomy that
maps typed errors onto those codes.

Nothing works yet. Everything after this is additive.

**Done when:** `kleidos` builds and every verb exits 120 with "not implemented".

## Stage 2 — Storage and crypto core (no CLI)

- XDG path resolution (`$XDG_DATA_HOME`, falling back to `~/.local/share`).
- Identity and recipients loading. Every write re-encrypts to *all* recipients.
- Vault format: version refusal, sorted keys, `[A-Z_][A-Z0-9_]*` validation,
  `fpkey` generated once at creation.
- The write path, exactly as the handoff specs it: separate never-unlinked lock
  file, deferred unlink registered at temp creation, `w.Close()` before `Sync()`,
  stat-then-hardlink `.bak`, rename, **directory** fsync.

The load-bearing stage. Testable headlessly, with no verbs.

**Done when:** Stage 3 is green.

## Stage 3 — Write-path test harness

A separate stage because one green run proves nothing — it is a race.

- 50 concurrent writers x 20 runs on ext4 under `/home` (**not** `/tmp`, which is
  tmpfs here: `fsync` there succeeds without doing anything).
- Assert all 50 keys survive every run, and zero leftover temp files.
- Assert `.bak` shares an inode with the pre-rename vault, and that it still
  decrypts to the previous contents. The transient link count of 2 is not
  observable from outside the write; a shared inode implies it.
- Run the deliberately broken-lock variant (unlink the lock after release) and
  confirm the count actually drops on this filesystem, rather than assuming it.

**Done when:** 20/20 runs keep 50/50 keys, and the broken variant demonstrably loses.

## Stage 4 — Write verbs

`set` (prompt on `/dev/tty` with echo off, terminal state restored on SIGINT,
`--stdin`), `delete`, `rename` (refuses on collision, `--force` to clobber,
**preserves `updated`**).

NUL rejection lands here. After this stage, "no value contains NUL" is an
invariant every later consumer relies on rather than re-checks.

## Stage 5 — Read verbs

`get` (gated on `isatty(2)`, exit 125, no override flag), `list` (names,
timestamps, `HMAC-SHA256(fpkey, value)` truncated to 8 hex), `reveal` (with `-0`
as *the* machine-readable path, not a niche flag).

Multi-key `get`/`reveal` are all-or-nothing: on any miss, fail non-zero and list
**every** missing name. Distinguish "key absent" from "key present, value empty".

## Stage 6 — `export`

Its own stage because the output is `eval`-ed, so a quoting bug is arbitrary code
execution.

- `shellQuote`: wrap in single quotes, escape embedded `'` as `'\''`, return
  `(string, error)` so NUL fails loudly rather than truncating.
- Validate key names at **emit** time, not just on import — the left-hand side of
  an `eval`-ed assignment is its own injection point.
- Fuzz against dash and bash as genuinely distinct binaries. `/bin/sh` is bash on
  this machine, so the tests invoke `dash` by name.

## Stage 7 — `run`

`--` required (error clearly if absent). Decrypt, build child env, `execve` —
never fork-and-wait, which buys correct signal handling and exit-code propagation
for free. Fails before exec if decryption fails, so the child never runs with a
blank credential. Secrets win on collision, with a warning on stderr. `127` when
the command does not exist, `126` when it exists but is not executable.

## Stage 8 — `import`

Pure parsing, lowest risk, so it goes last. Strict `.env` subset; everything else
rejected loudly with a line number. Collision policy refuses by default and lists
every colliding name; `--overwrite` and `--skip-existing` are all-or-nothing.

## Stage 9 — Hardening and docs

`RLIMIT_CORE` to 0, best-effort zeroing at the edges, flush-and-check on `reveal`
output. README stating the threat model as honestly as the handoff does —
**there is no boundary against the agent in v1** — plus setup steps and the
permission rules to paste in.

Then verify the permission matrix against the real binary. This needs a Claude
Code restart, so it is the user's step, not the build's. Rules added mid-session
are inert until restart and fail open with no feedback.

---

## Deliberate non-goals for v1

Restated from the handoff so they are not re-litigated mid-build: no `--env-file`
or `secrets://` references, no `--prefix`/`--strip`, no `edit`, no audit log, no
shell completions, no provider abstraction, no output masking in `run`, no session
lock. The session lock is the only deferred item that would produce an actual
boundary, and it costs unattended operation to get it.

## Things not to "fix" later

- **Reads take no lock.** `rename` is atomic, so a reader gets the old inode or
  the new one, whole. Acquiring the lock in `get` would serialize every read
  against every write for no correctness gain, and let a stuck writer block reads.
- **The lock file is never unlinked.** `flock` locks an inode, not a path.
- **`[]byte` discipline stops at the edges.** `encoding/json` produces
  uncontrollable `string` copies; half-implementing the stricter rule gives the
  appearance of a guarantee with none of the substance.

---

## Measured on this machine

Recorded here rather than silently absorbed, per the handoff's instruction to
trust the machine and note the disagreement.

| | reference machine | here (Linux 7.1.11, ext4, nvme) |
|---|---|---|
| 50 writers x 20 runs, sound lock | 50/50 every run, no temp files | same |
| broken-lock variant | lost on **every one** of 20 runs, 36-64% | lost in **11 of 20** runs, worst kept 22/50 |
| `link: file exists` TOCTOU under broken lock | observed | observed, 1-2 writers per losing run |

The broken-lock variant loses less *often* here, but when it loses it loses just
as hard. The mechanism reproduces exactly; only the race window differs, which is
what you would expect from a faster disk. It is still demonstrably load-bearing,
which is the only thing the test needs to establish.

One consequence: because it fails on roughly half of runs rather than all of
them, the control needs the full 20 runs to be trustworthy, so it skips under
`-short` rather than reporting a false pass at two runs.
