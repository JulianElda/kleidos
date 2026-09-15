# Measured findings

Results that were observed rather than reasoned. Every one is a property of the
environment below; a finding without its environment is a rumor. The procedures
for re-measuring these are in [verifying.md](verifying.md).

| | |
|---|---|
| measured | 2026-09-02, re-confirmed 2026-09-03 |
| kernel | Linux 6.18.33.2 (WSL2), x86_64 |
| distro | Arch Linux |
| filesystem | ext4 (`/tmp` is tmpfs and deliberately avoided) |
| Go | 1.27.0 |
| age library | `filippo.io/age v1.3.2` |
| shells | dash 0.5.13.4, bash 5.3.15 — note `/bin/sh` is bash on Arch |
| `ptrace_scope` | 1 (restricted) |
| `/proc/self/cmdline` | `0444` — world-readable |
| `/proc/self/environ` | `0400` — owner-only |
| Claude Code | version not recorded; assume stale |

The `/proc` asymmetry in the last two rows is what `run`'s entire design rests
on. `ptrace_scope` at 1 is the second layer under it.

The clipboard section was measured on a different machine, which a WSL2 kernel
could not have stood in for; its environment is given there.

---

## Write path under concurrency

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

## `shellQuote`

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

## dash corrupts some high bytes through command substitution

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

## Permission rules

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

## Clipboard

| | |
|---|---|
| measured | 2026-09-15 |
| kernel | Linux 7.2.5, x86_64 |
| distro | NixOS 26.11 |
| session | KDE Plasma 6.7.5 on Wayland (KWin 6.7.5), XWayland 24.1.13 |
| Go | 1.26.7 |

The built binary was driven under `script` so stderr was a terminal, against a
scratch vault holding a dummy value, and observed with `wl-paste`, `ps` and
Klipper's D-Bus history.

- **KWin advertises `ext_data_control_manager_v1` only**, not the wlroots
  protocol, so the Wayland path measured here is the ext one. The wlroots path is
  covered by the fake compositor in the tests, not by a real one.
- **Both backends round-trip the value** byte for byte, and both offer
  `x-kde-passwordManagerHint`. KWin relays an X11 owner's targets to Wayland
  clients, the hint included.
- **Klipper records neither.** Control: the same dummy value copied with plain
  `wl-copy`, without `--sensitive`, was recorded at once.
- **Once a value is in Klipper's history, clearing brings it back.** After the
  control above, a `copy` of the same value cleared on time and its process
  exited, yet the value stayed pasteable: Klipper had refilled the emptied
  clipboard from its newest history entry, offering
  `application/x-kde-onlyReplaceEmpty` and no password hint. `copy` cannot help a
  secret that reached history some other way, such as `get FOO | wl-copy`.
- **The background process's argv is `kleidos __copy-serve 4s`** for a 4s
  deadline. At the deadline the clipboard is empty and the process gone, on both
  backends.
- **Copying something else ends the Wayland server at once. It does not end the
  X11 server under XWayland:** no `SelectionClear` arrived when `wl-copy` took the
  clipboard. Why is not established; KWin bridging the X11 selection only while
  an X11 window has focus is a guess. The X11 server lives to its deadline, and
  relinquishing then left the newer value in place.
- **Without `WAYLAND_DISPLAY` and `DISPLAY`**, `copy` exits 120 naming both
  reasons, after the server reports; `copied` is not printed.
