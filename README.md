# kleidos

Key/value secrets in a single [age](https://age-encryption.org)-encrypted file,
for use by a human and by an agent.

No secret is ever passed in `argv`. Plaintext does not reach a terminal or a
transcript by default, and the two commands that do dump plaintext are separate
verbs so a permission layer can gate them individually.

Design rationale and measured findings live in
[claude-insights.md](claude-insights.md); you do not need any of it to use the
tool.

## Before you store anything real

kleidos has **no boundary against an agent running as your user.** The identity
has no passphrase, and permission rules are bypassable by path spelling. It
reduces blast radius; it does not confine.

**Assume any secret an agent has handled may be in a transcript, and make
rotation cheap.** Rotation is the recovery path, and it is the only one.

## Install

```bash
go build -o ~/.local/bin/kleidos .
```

Single static binary, no runtime dependencies.

## Setup

```bash
mkdir -p ~/.local/share/kleidos
chmod 700 ~/.local/share/kleidos
age-keygen -o ~/.local/share/kleidos/identity
chmod 600 ~/.local/share/kleidos/identity
age-keygen -y ~/.local/share/kleidos/identity \
  > ~/.local/share/kleidos/recipients
```

**Then, before storing anything real,** add a break-glass recipient:

```bash
age-keygen -o "$XDG_RUNTIME_DIR/breakglass.key"
age-keygen -y "$XDG_RUNTIME_DIR/breakglass.key" \
  >> ~/.local/share/kleidos/recipients
cat "$XDG_RUNTIME_DIR/breakglass.key"    # copy this off the machine, then rm it
```

A recipient can only be added while the vault can still be decrypted. Lose the
only identity and everything in it is unrecoverable. Every write re-encrypts to
every recipient, so adding one now costs nothing later.

The same mechanism covers two machines: each keeps its own identity, both public
keys go in `recipients`, and nothing sensitive travels between them.

`$XDG_DATA_HOME` is respected, and `$KLEIDOS_DIR` overrides the directory
outright. Nothing in this directory may enter `/nix/store`.

## Commands

```
kleidos set KEY [--stdin]         store a value
kleidos get KEY [KEY...]          print values; terminal only
kleidos reveal [-0] KEY [KEY...]  print values unconditionally
kleidos list                      names, update times, fingerprints
kleidos delete KEY                remove a key
kleidos rename OLD NEW [--force]  rename, preserving the update time
kleidos run --only K1,K2 -- cmd   exec cmd with those secrets in its environment
kleidos export                    emit shell assignments for eval
kleidos import FILE [--overwrite|--skip-existing]
```

Every command needs the identity, including `list`.

### set

```bash
kleidos set DB_PASSWORD              # prompts on the terminal, echo off
printf %s "$value" | kleidos set DB_PASSWORD --stdin
```

There is no positional value argument, because `argv` is world-readable via
`/proc/<pid>/cmdline`.

`--stdin` stores exactly the bytes it reads and does **not** strip a trailing
newline. Use `printf %s`, not `echo`, unless you want the newline stored.

Key names must match `[A-Z_][A-Z0-9_]*`. Values may not contain NUL.

### get and reveal

`get` prints plaintext only when stderr is a terminal, and otherwise exits 125.
There is no flag that overrides this; the override is `reveal`.

```bash
kleidos get DB_USER                  # prints the value plus a newline
kleidos get DB_USER DB_PASSWORD      # several keys print as KEY=value lines
kleidos get DB_USER > secret.txt     # works: stderr is still a terminal
```

`reveal` takes the same arguments and skips the terminal check.

**In scripts, use `reveal -0`:**

```bash
kleidos reveal -0 DB_USER DB_PASSWORD    # NUL-delimited, request order
```

`K=$(kleidos reveal FOO)` silently discards trailing newlines, which matters for
certificate and key material. Under dash it can also corrupt some high bytes.

If any requested key is missing, nothing is printed, every missing name is
listed, and the command exits 121. "Absent" and "present but empty" are
different states.

### list

```
NAME         UPDATED               FINGERPRINT
DB_PASSWORD  2026-09-02T17:34:58Z  f50e7975
DB_USER      2026-09-02T17:34:58Z  28530f2e
```

No plaintext is printed. The fingerprint is a keyed digest of the value: equal
fingerprints mean equal values, and it tells you nothing else. Use it to confirm
two machines hold the same secret, or that a write landed.

### rename

Refuses when the new name already exists, and names the collision. `--force`
overwrites. The update time is preserved: the value did not change, only its
name.

### run

```bash
kleidos run --only DB_USER,DB_PASSWORD -- psql -h localhost
```

Both `--` and `--only` are required. Values land in the child's `environ`
(`0400`, owner-only) rather than `argv` (`0444`, world-readable). The child's
exit status passes through unmodified.

If a key is missing or decryption fails, the command does not start. If a named
secret shadows an inherited environment variable, the vault value wins and a
warning goes to stderr.

`run` makes no promise about what the child does with the value. A child that
prints its environment leaks.

### export

```bash
eval "$(kleidos export)"
```

Use the quoted form. Unquoted, `eval $(kleidos export)` word-splits the output
and turns newlines inside values into spaces.

### import

```bash
kleidos import .env
kleidos import .env --overwrite        # replace colliding keys
kleidos import .env --skip-existing    # keep the vault's versions
```

Accepts `KEY=value` (optionally `export `-prefixed), blank lines, `#` comments on
their own line, and values wrapped in matching single or double quotes. **No
expansion is performed** in either quote style.

Rejected, with a line number: trailing comments, line continuations, multi-line
values, unmatched quotes, spaces around `=`, duplicate keys, NUL, stray carriage
returns, invalid key names.

If any key already exists, nothing is imported and every collision is listed.
Both flags apply to the whole file or not at all.

## Claude Code permission rules

Add to `~/.claude/settings.json`:

```json
"permissions": {
  "allow": [
    "Bash(kleidos set:*)",
    "Bash(kleidos get:*)",
    "Bash(kleidos list:*)",
    "Bash(kleidos delete:*)",
    "Bash(kleidos rename:*)",
    "Bash(kleidos import:*)",
    "Bash(kleidos run:*)"
  ],
  "ask": [
    "Bash(kleidos reveal:*)",
    "Bash(kleidos export:*)"
  ],
  "deny": [
    "Read(//home/<you>/.local/share/kleidos/identity)"
  ]
}
```

**The doubled leading slash in the `Read` rule is required.** With a single slash
the rule matches nothing and the identity is readable, with no warning of any
kind. Write the absolute path, not `~`.

**Restart Claude Code afterwards.** Rules added mid-session are inert until
restart and fail open with no feedback.

Then verify, because a gate that fails open silently is worse than no gate:
temporarily change `reveal` from `ask` to `deny`, restart, run
`kleidos reveal ANY_KEY`, confirm a visible denial, change it back, restart
again. Anything less than a visible denial means the rules are not loaded.

These rules stop accidents, not a determined caller: `./kleidos reveal FOO` and
an absolute path both bypass them. See
[claude-insights.md](claude-insights.md#permission-rules) for what was measured.

## Exit codes

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

Codes sit at 120 and above so that **any code below 120 came from a `run` child,
unmodified**.

## Storage

```
~/.local/share/kleidos/        (0700)
├── identity          AGE-SECRET-KEY-1...   (0600)
├── recipients        one age1... per line  (plaintext, readable)
├── lock              empty, never unlinked (0600)
├── secrets.age       the vault             (0600)
└── secrets.age.bak   the previous vault    (0600)
```

Every mutation, delete included, rewrites the whole blob and replaces it
atomically. `secrets.age.bak` holds the previous ciphertext until the next write.

Do not delete `lock`. Do not assume file sync between machines gives you
multi-machine writes — it is a single blob, last write wins.

## Not in v1

Audit log, an `edit` verb, session lock, provider abstraction, YubiKey-backed
prod tier, output masking in `run`, `--env-file` / `secrets://` references,
`--prefix` / `--strip`, shell completions.

## Development

```bash
go test ./...              # full suite, including the 20x50 write-path stress
go test -short ./...       # skips the long stress runs
go test ./internal/cmd/ -run '^$' -fuzz FuzzShellQuote -fuzztime 60s
```

Two requirements the suite checks at runtime rather than assuming:

- **Write-path tests refuse to run on tmpfs**, where `fsync` is a no-op. They use
  `~/.cache/kleidos-test` by default; override with `KLEIDOS_TEST_SCRATCH`.
- **`dash` and `bash` must both be installed and be different binaries.**
  `/bin/sh` is bash on Arch, so the suite resolves both by name and fails rather
  than testing bash twice.

`KLEIDOS_DIR` overrides the vault directory, which is how tests avoid touching a
real one.
