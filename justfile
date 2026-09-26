# kleidos development tasks.
#
# This file names commands and keeps the reasons out. A recipe that restates
# rationale is a second copy of it, and the copy is the one that goes stale,
# silently, with nothing failing when it does.

# just's default shell is sh, and this repo cares that sh is dash on some
# machines and bash on others -- shells() in the suite resolves both by name
# rather than trusting sh. Pin bash here for the same reason.
set shell := ["bash", "-euo", "pipefail", "-c"]

# List the recipes.
default:
    @just --list

# gofmt -l only lists its findings and still exits 0, so the emptiness test is
# what turns unformatted files into a failure.

# Format, vet, lint, then the full suite -- the pre-commit gate.
check:
    @test -z "$(gofmt -l .)" || { gofmt -l .; echo "gofmt: the files above need formatting"; exit 1; }
    go vet ./...
    golangci-lint run
    go test ./...

# The suite. `just test -short` drops the stress run; see CLAUDE.md.
test *ARGS:
    go test ./... {{ARGS}}

# shellQuote is a code-execution surface, so it is fuzzed rather than trusted.
fuzz TIME="60s":
    go test ./internal/cmd/ -run '^$' -fuzz FuzzShellQuote -fuzztime {{TIME}}

# Deliberately not part of `check`: these are properties of the kernel and the
# harness, not of kleidos, so a difference means the recorded findings need
# updating rather than that the code is broken. The one environment fact that
# does invalidate a test -- a tmpfs scratch dir -- is enforced by the suite
# itself, in internal/testenv. Each check's heading line says what it guards.

# Re-check the environment facts the recorded findings rest on.
doctor:
    #!/usr/bin/env bash
    set -uo pipefail

    status=0
    ok()      { printf '  ok       %s\n' "$1"; }
    differs() { printf '  DIFFERS  %s\n' "$1"; status=1; }
    note()    { printf '  note     %s\n' "$1"; }

    echo "1. /proc asymmetry -- why run puts values in environ, never in argv"
    cmdline=$(stat -c %a /proc/self/cmdline 2>/dev/null || echo "?")
    environ=$(stat -c %a /proc/self/environ 2>/dev/null || echo "?")
    if [[ $cmdline == 444 && $environ == 400 ]]; then
        ok "cmdline 444, environ 400"
    else
        differs "cmdline $cmdline (expected 444), environ $environ (expected 400)"
    fi

    echo "2. ptrace hardening -- the second layer under run"
    scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)
    case $scope in
        1)      ok "ptrace_scope 1 (restricted)" ;;
        0)      differs "ptrace_scope 0 -- a peer process can attach; that layer is gone" ;;
        absent) differs "no yama/ptrace_scope -- this kernel has no Yama LSM" ;;
        *)      note "ptrace_scope $scope (stricter than the recorded 1)" ;;
    esac

    echo "3. scratch filesystem -- write-path durability is untestable on tmpfs"
    scratch=${KLEIDOS_TEST_SCRATCH:-$HOME/.cache/kleidos-test}
    probe=$scratch
    while [[ ! -e $probe && $probe != / ]]; do probe=$(dirname "$probe"); done
    fstype=$(stat -f -c %T "$probe" 2>/dev/null || echo "?")
    where=$probe
    [[ $probe == "$scratch" ]] || where="$probe (nearest existing ancestor of $scratch)"
    if [[ $fstype == tmpfs ]]; then
        differs "$where is tmpfs -- the suite will refuse; set KLEIDOS_TEST_SCRATCH"
    else
        ok "$where is $fstype"
    fi

    echo "4. descriptor state -- the get gate reads stderr, not stdout"
    if [[ -t 2 ]]; then
        note "stderr here is a TTY: a human terminal, so get will emit"
    else
        note "stderr here is not a TTY: an agent harness, so get will refuse"
    fi
    if command -v script >/dev/null 2>&1; then
        under=$(script -qec "test -t 2 && echo TTY || echo NOTTY" /dev/null | tr -d "\r\n")
        if [[ $under == TTY ]]; then
            ok "stderr under a pty is a TTY -- the control holds"
        else
            differs "stderr under a pty reported $under -- the control failed"
        fi
    else
        note "script(1) absent -- skipped the pty control"
    fi

    echo
    if (( status == 0 )); then
        echo "matches the recorded findings"
    else
        echo "something differs from the recorded findings -- trust this machine, fix the record"
    fi
    exit $status
