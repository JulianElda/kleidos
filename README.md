# kleidos

Key/value secrets in a single [age](https://age-encryption.org)-encrypted file.

The name is κλειδός, genitive of κλείς — "of the key," the same root behind
*clavis* and *clavicle*. It is a personal tool, not an Anthropic product.

The primary caller is an agent rather than a human, which drives most of the
design: no secret is ever passed in `argv`, plaintext does not reach a
transcript by default, and the operations that do dump plaintext are separate
verbs so a permission layer can gate them individually.

## Read this before you store anything real

**There is no boundary against an agent running as you.** Not a weak one — none.
Two reasons, and they compound:

1. **The identity has no passphrase, by choice.** It is usable by anything
   running as your user. That is what makes unattended operation work, and it is
   the whole reason there is no cryptographic boundary. These are the same fact
   stated twice.
2. **Claude Code's permission matcher is bypassable.** Any path spelling other
   than the bare name — `./kleidos get FOO`, or an absolute path — slips past a
   rule written against the name, measured and still true. Shell nesting
   (`sh -c '...'`) was stopped, but by a different layer whose coverage is
   undocumented; see "What the matcher actually catches" below.

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

## Install

```bash
go build -o ~/.local/bin/kleidos .
```

Single static binary, no runtime dependencies. `age` is used as a library, not
shelled out to, so plaintext stays in-process.

## Setup

```bash
mkdir -p ~/.local/share/kleidos
chmod 700 ~/.local/share/kleidos
age-keygen -o ~/.local/share/kleidos/identity
chmod 600 ~/.local/share/kleidos/identity
age-keygen -y ~/.local/share/kleidos/identity \
  > ~/.local/share/kleidos/recipients
```

**Then, before storing anything real:** generate a second identity as a
break-glass backup, add its public key as a second line in `recipients`, and keep
the private half off the machine — a USB stick, printed, a password manager.

```bash
age-keygen -o /tmp/breakglass.key          # then move this off the machine
age-keygen -y /tmp/breakglass.key >> ~/.local/share/kleidos/recipients
```

A recipient can only be added while the vault can still be decrypted. Lose the
only identity and everything in it is unrecoverable. Every write re-encrypts to
every recipient, so adding one now costs nothing later.

The same mechanism covers two machines: each keeps its own identity, both public
keys go in `recipients`, and nothing sensitive travels between them.

`$XDG_DATA_HOME` is respected. Nothing in this directory may enter `/nix/store` —
the identity stays imperative even if configuration later becomes declarative.

## Commands

```
kleidos set KEY                  store a value, prompting with echo off
kleidos set KEY --stdin          store a value read from stdin, verbatim
kleidos get KEY [KEY...]         print values; refuses unless stderr is a terminal
kleidos reveal [-0] KEY [KEY...] print values unconditionally
kleidos list                     names, update times, fingerprints
kleidos delete KEY               remove a key
kleidos rename OLD NEW [--force] rename, preserving the update time
kleidos run --only K1,K2 -- cmd  exec cmd with those secrets in its environment
kleidos export                   emit shell assignments for eval
kleidos import FILE              load a strict subset of .env
```

There is deliberately no positional value on `set`: `argv` is world-readable.

### `get` versus `reveal`

`get` prints plaintext **only when stderr is a terminal**, and otherwise exits
125. There is no flag that overrides this — the override is a different command.

The check is on stderr, not stdout, because under an agent harness all three
descriptors are non-TTY, so stderr is a terminal exactly when a human one is
present. That means `get FOO > file` and `get FOO | pbcopy` still work for a
human, while a captured invocation refuses.

**This stops accidents, not intent.** An agent that wants the value runs
`reveal`, or spells the path differently, or allocates a pty — all work. The
property worth having is that plaintext does not reach a transcript by default,
and that putting it there is a distinct, promptable act.

### Reading values into scripts

Use `reveal -0`. It emits NUL-delimited values in request order, and NUL is
guaranteed absent from values because both write paths reject it.

`K=$(kleidos reveal FOO)` is **silently lossy**: command substitution discards
trailing newlines, and key and certificate material is exactly the category that
has them. Under dash it is worse — dash also corrupts some high bytes on
substitution into a variable, independently of anything this tool does.

### `export`

```bash
eval "$(kleidos export)"
```

Use the quoted form. Unquoted, `eval $(kleidos export)` word-splits the output
and turns newlines inside values into spaces.

Every value is single-quoted with embedded quotes escaped as `'\''`, and key
names are re-validated at emit time — the left-hand side of an `eval`-ed
assignment is its own injection point.

### `run`

```bash
kleidos run --only DB_USER,DB_PASSWORD -- psql -h localhost
```

`--` is required. `--only` is required too: children inherit the whole
environment and so do grandchildren, so there is no way to inject the whole
vault.

Values land in the child's `environ` (mode `0400`, owner-only) rather than
`argv` (`0444`, world-readable). That asymmetry is the entire point. kleidos
`execve`s rather than forking, so signal handling and exit-code propagation come
out correct for free, and decryption failure stops the command before it starts
with a blank credential.

**What `run` does not guarantee:** anything about the child's output. A child
that prints its environment leaks, and `run --only K -- sh -c 'echo $K'` is a
deliberate read. No check prevents that, and a name-based check on shell
interpreters would break legitimate use while being defeated by `env`, `make`, or
any other wrapper.

### `import`

Accepts a strict subset of `.env` and rejects everything else with a line
number, because a silently mis-parsed value stored as a secret is discovered at
the worst possible moment.

Accepted: `KEY=value`, optionally `export `-prefixed; blank lines; `#` comments
on their own line; values optionally wrapped in matching single or double quotes.
**No expansion is ever performed** in either quote style — a `.env` file is data,
not a script.

Rejected: trailing comments, line continuations, multi-line values, unmatched
quotes, spaces around `=`, duplicate keys, NUL, stray carriage returns, and
invalid key names.

If any key already exists, nothing is imported and every collision is listed.
`--overwrite` replaces them, `--skip-existing` keeps the vault's versions; either
way it is all or nothing.

## Claude Code permission rules

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

**The doubled leading slash in the `Read` rule is load-bearing.** Written with a
single slash the rule matches nothing and the identity is readable, with no
warning of any kind. This was measured, not reasoned: with
`Read(/home/.../identity)` the file came back in full, secret key included. A
single slash appears to be resolved relative to the project directory. This is
the failure mode that matters most, because a rule that fails open is worse than
no rule — it is trusted.

`run` stays `allow` because prompting on every ordinary command defeats the tool,
and because `run` offers no guarantee a prompt would be protecting.

**Rules added mid-session are inert until you restart, and they fail open with no
feedback.** Someone who adds these and keeps working believes they are protected
and is not.

To verify: temporarily change `reveal` to `deny`, restart, run
`kleidos reveal ANY_KEY`, confirm a visible denial, set it back, restart again.
Anything less than a visible denial means the rules are not loaded.

### What the matcher actually catches

Measured on 2026-09-02 against the real binary, with `reveal` temporarily set to
`deny` so that every outcome left an observable artifact. These are properties of
one Claude Code version on one machine and are worth re-running.

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
compound commands, variable indirection, and treats `env` as a pass-through
wrapper. Both path-spelling bypasses remain open.

**The `sh -c` row is the one to read carefully.** It was blocked, but the refusal
came from the auto-mode classifier — a separate mechanism with different
coverage, which fires on how a command looks rather than what it does. Whether
the matcher itself still has that hole is therefore undetermined. Do not count
the classifier: it is undocumented, and testing only alarming-looking commands
will lead you to conclude the rules are tighter than they are.

One finding runs the other way. A Bash command reading the identity path
(`sha256sum .../identity`) was **also** refused by the permission system, while
the same command against `recipients` in the same directory ran — so on this
version the `Read` deny rule extends to Bash rather than being confined to the
Read tool. That is better than assumed, and it is still policy rather than kernel
enforcement: treat it as a courtesy, not a boundary.

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

Codes sit at 120 and above deliberately. The range 1–7 collides maximally with
real programs — `psql` returns 3, `git` returns 1/2/128, `curl` uses 1 through 92
— and `run` execs a child whose status passes through unmodified. **Any code
below 120 came from the child.** 126, 127 and 128+n follow the shell conventions.

Multi-key `get` and `reveal` are all-or-nothing: a miss fails the whole call and
names every missing key, because returning a username with an empty password is
the dangerous outcome. "Absent" and "present but empty" are distinct.

## Storage

```
~/.local/share/kleidos/        (0700)
├── identity          AGE-SECRET-KEY-1...   (0600)
├── recipients        one age1... per line  (plaintext, readable)
├── lock              empty, never unlinked (0600)
├── secrets.age       the vault             (0600)
└── secrets.age.bak   the previous vault    (0600)
```

Every mutation, delete included, is a read-modify-write of the whole blob:
decrypt, mutate, re-encrypt, replace atomically. `.bak` is a hardlink to the
previous ciphertext, not a copy.

All metadata lives inside the ciphertext, so there is no plaintext index and
`list` requires the identity. Key names leak plenty on their own.

**Reads take no lock.** `rename` is atomic, so a reader opens either the old
inode or the new one, whole, and never a torn file. This is a decision, not an
oversight: locking reads would serialize every read against every write for no
correctness gain and would let a stuck writer block reads.

## Known limits

- **No boundary against an agent.** Enforcement is policy, the policy layer is
  bypassable at least two ways, and the identity has no passphrase.
- No time bound. The identity is usable by anything running as you, indefinitely.
- A single blob means mutations require decryption, so write-only-for-an-agent is
  not available.
- Plaintext exists as uncontrollable `string` copies during JSON decode. Zeroing
  covers the edges only, and the GC may have moved the data anyway.
- `run` guards its own stdout and argv, not the child's. `reveal` and `export`
  are explicit dumps.
- Syncing the vault between machines can silently lose writes: single blob,
  last-write-wins. Do not assume sync gives you multi-machine writes.
- Permission matcher behavior is version-dependent. The table below was measured
  once, on one version, on one machine, and a `Read` rule written the obvious way
  turned out to protect nothing at all.

## Not in v1

Audit log, an `edit` verb, session lock (passphrase-wrapped identity with a
cached unwrapped key and a TTL), a provider abstraction, a YubiKey-backed prod
tier, output masking in `run`, `--env-file` / `secrets://` references,
`--prefix` / `--strip`, and shell completions.

The session lock is the only one of those that would produce an actual boundary,
and it costs unattended operation to get it. It is worth promoting the moment
unattended operation stops being the priority.

## Development

```bash
go test ./...              # full suite, including the 20x50 write-path stress
go test -short ./...       # skips the long stress runs
go test ./internal/cmd/ -run '^$' -fuzz FuzzShellQuote -fuzztime 60s
```

Two things the test suite depends on, both checked at runtime rather than
assumed:

- **Write-path tests refuse to run on tmpfs.** `fsync` there succeeds without
  doing anything, which makes the durability half of the test theatre. They use
  `~/.cache/kleidos-test` by default; override with `KLEIDOS_TEST_SCRATCH`.
- **`shellQuote` is verified against dash and bash**, and the suite fails if they
  resolve to the same binary. `/bin/sh` is bash on Arch, so a suite that ran `sh`
  and then `bash` would test bash twice and report a false pass on the one
  function where being wrong is arbitrary code execution.

`KLEIDOS_DIR` overrides the vault directory, which is how the tests avoid
touching a real one.
