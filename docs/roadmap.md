# Roadmap

## Not in v1

Restated so they are not re-litigated: no audit log, no `edit` verb, no session
lock, no provider abstraction, no YubiKey-backed prod tier, no output masking in
`run`, no `--env-file` or `secrets://` references, no `--prefix`/`--strip`, no
shell completions.

The session lock is the only one of these that would produce an actual boundary,
and it costs unattended operation to get it. See
[threat-model.md](threat-model.md).

---

## Deferred, in rough priority order

1. **Audit log.** Append-only; log which provider resolved, once providers
   exist.

2. **`edit` verb** via a `$XDG_RUNTIME_DIR` temp file. Editor swap and undo
   files are the footgun — they land next to the temp file and outlive it.

3. **Session lock.** Passphrase-wrapped identity (`age -p`), unwrapped key
   cached in `$XDG_RUNTIME_DIR` with an absolute TTL, `unlock`/`lock` verbs.
   **The only item here that produces an actual boundary**, and it costs
   unattended operation to get it. Promote it the moment unattended operation
   stops being the priority.

4. **Provider abstraction.** `resolve() → age identity`, config-ordered, and
   **never** silently falling through from "configured but locked" to a weaker
   source. KeePassXC via Secret Service is the intended first provider.

5. **Prod tier.** A separate vault encrypted to an `age-plugin-yubikey`
   recipient. Plugin stanzas require shelling out to the `age` binary, so keep
   the encrypt/decrypt call site swappable.
