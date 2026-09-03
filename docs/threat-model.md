# Threat model

What kleidos protects against, what it does not, and where enforcement sits. Read
this before trusting the tool with anything. An early draft of the design claimed
the security boundary lived in Claude Code's permission rules; that was tested and
is false.

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

## Where enforcement sits

Permission rules are applied per verb: everything that cannot print plaintext is
`allow`, the two verbs that dump plaintext are `ask`, and the identity file is
`deny` for `Read`. The rules to paste are in the README.

`run` stays `allow` because prompting on every ordinary command defeats the tool,
and because `run` offers no guarantee a prompt would be protecting: it hands the
value to a child and has no control after `execve`.

There is a second, independent layer — an auto-mode classifier that fires on how
a command *looks* rather than on what it does. **Do not count it.** It is
undocumented, its coverage differs from the matcher's, and during measurement it
masked a rule failure that only appeared once an alarming-looking flag was
removed. Testing only obvious-looking commands will lead you to conclude the
rules are tighter than they are.

What the matcher does and does not catch was measured; see
[findings.md](findings.md#permission-rules). The procedure for re-measuring it is
in [verifying.md](verifying.md).

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
