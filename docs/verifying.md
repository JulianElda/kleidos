# Re-check procedures

Findings in [findings.md](findings.md) were taken once, on one machine, on one
Claude Code version. These are the procedures that re-take them.

If a re-check disagrees with what is recorded, **trust your machine and fix the
document.** Note the disagreement rather than working around it silently.

## The four one-liners

```bash
# 1. /proc asymmetry -- justifies `run`'s entire design
ls -l /proc/self/environ /proc/self/cmdline      # expect 0400 and 0444

# 2. ptrace hardening -- the second layer under `run`
cat /proc/sys/kernel/yama/ptrace_scope           # 1 = restricted; 0 loses a layer

# 3. scratch filesystem -- write-path durability tests are meaningless on tmpfs
stat -f -c %T ~/.cache/kleidos-test              # must not be tmpfs

# 4. descriptor state under the harness -- the `get` check depends on this
test -t 2 && echo TTY || echo NOTTY              # expect NOTTY under Claude Code
script -qc 'test -t 2 && echo TTY || echo NOTTY' /dev/null   # expect TTY
```

Both halves of the fourth are now also asserted by `main_test.go`, which opens
its own pty rather than shelling out to `script`: it puts a terminal on the
child's stderr while stdout stays a pipe, which is the arrangement the gate was
designed around and the one `script` cannot express. Keep the one-liner: it is
what tells you whether *this harness* still presents no TTY, which is a fact
about the environment rather than about kleidos.

---

## Verifying the permission rules

The fifth check, and the most likely of them to have changed. Three properties
of the harness shape the procedure:

1. **Rules added mid-session are inert until restart, and fail open with no
   feedback.** This voided an entire test run during the original work. Always
   restart after editing settings.
2. **`ask` prompts leave no artifact an agent can observe.** Only denials appear
   in the transcript, so test with `deny` rules rather than `ask` rules — that is
   what makes the behavior machine-checkable. Confirmed equivalent on at least
   one case that prompted under `ask` and was denied under `deny`.
3. **No shell state persists between tool calls** — no `export PATH=…`, no `cd`,
   no functions. Each case must be its own invocation, and prefixing
   `PATH=… cmd` changes the command string, which is the thing under test.
   Install the stub somewhere already on `PATH`.

Put a stub script named `kleidos` on `PATH` that echoes its arguments, set `get`
and `export` to `deny`, restart, then run each of these as a separate invocation
and record which are denied:

```
kleidos list                            # expect: runs
kleidos get FOO                         # expect: denied
kleidos get FOO --reveal                # expect: denied by get:*, not the flag
kleidos  get FOO                        # two spaces -- expect: denied
echo hi && kleidos get FOO              # expect: denied
X=kleidos; $X get FOO                   # expect: denied
env kleidos get FOO                     # expect: denied
sh -c 'kleidos get FOO'                 # expect: RUNS -- the bypass
./path/to/kleidos get FOO               # expect: RUNS -- the bypass
/abs/path/to/kleidos get FOO            # expect: RUNS -- the bypass
```

Keep the alarming flag *off* the `sh -c` case. With `--reveal` attached the
classifier blocks it, and you will wrongly conclude the rule caught it.

Then check persistence separately under real `ask` rules: run the same command
twice and see whether the second prompts.

**Delete the stub when finished.** A script named `kleidos` on `PATH` shadows the
real binary, and it is a genuinely confusing failure to debug.
