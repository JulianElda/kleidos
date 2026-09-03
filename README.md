# kleidos

Key/value secrets in a single [age](https://age-encryption.org)-encrypted file,
for use by by an agent.

No secret is ever passed in `argv`. Plaintext does not reach a terminal or a
transcript by default, and the two commands that do dump plaintext are separate
verbs so a permission layer can gate them individually.

**Assume any secret an agent has handled may be in a transcript, and make
rotation cheap.**

## Install

```bash
go build -o ~/.local/bin/kleidos .
```

## Setup

```bash
# the vault directory
mkdir -p ~/.local/share/kleidos
chmod 700 ~/.local/share/kleidos

# the identity that decrypts the vault
age-keygen -o ~/.local/share/kleidos/identity
chmod 600 ~/.local/share/kleidos/identity

# its public key, as the first recipient
age-keygen -y ~/.local/share/kleidos/identity \
  > ~/.local/share/kleidos/recipients
```

Make a backup key:

```bash
# a second identity, never written to disk
key=$(age-keygen 2>/dev/null)

# its public key, appended to the recipients
printf '%s\n' "$key" | age-keygen -y \
  >> ~/.local/share/kleidos/recipients

# copy this off the machine
printf '%s\n' "$key"
unset key
```

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
kleidos set DB_PASSWORD              # prompts, echo off

# stores exactly the bytes read, trailing newline included
printf %s "$value" | kleidos set DB_PASSWORD --stdin
```

Key names must match `[A-Z_][A-Z0-9_]*`. Values may not contain NUL.

### get and reveal

```bash
kleidos get DB_USER                  # one key: the value plus a newline
kleidos get DB_USER DB_PASSWORD      # several: KEY=value lines
```

`get` requires stderr to be a terminal, `reveal` does not. Otherwise identical.
In scripts use `reveal -0`, which emits the values NUL-delimited in request
order:

```bash
kleidos reveal -0 DB_USER DB_PASSWORD
```

### list

```
NAME         UPDATED               FINGERPRINT
DB_PASSWORD  2026-09-02T17:34:58Z  f50e7975
DB_USER      2026-09-02T17:34:58Z  28530f2e
```

The fingerprint is a keyed digest: equal fingerprints mean equal values.

### rename

```bash
kleidos rename OLD_NAME NEW_NAME
kleidos rename OLD_NAME NEW_NAME --force   # overwrite an existing NEW_NAME
```

### run

```bash
kleidos run --only DB_USER,DB_PASSWORD -- psql -h localhost
```

Both `--only` and `--` are required. The child's exit status passes through.

### export

```bash
eval "$(kleidos export)"
```

### import

```bash
kleidos import .env
kleidos import .env --overwrite        # replace colliding keys
kleidos import .env --skip-existing    # keep the vault's versions
```

Accepts `KEY=value`, optionally `export `-prefixed, values optionally wrapped in
matching quotes; no expansion is performed. Blank lines and whole-line `#`
comments are ignored, anything else is rejected with a line number.

Without a flag, one existing key aborts the whole import.

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
