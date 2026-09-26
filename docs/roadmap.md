# Roadmap

## Not in v1

Restated so they are not re-litigated: no audit log, no `edit` verb, no session
lock, no provider abstraction, no YubiKey-backed prod tier, no output masking in
`run`, no `--env-file` or `secrets://` references, no `--prefix`/`--strip`, no
shell completions.

The session lock is the only one of these that would produce an actual boundary,
and it costs unattended operation to get it.

---

## Deferred, in rough priority order

1. **Files in the vault.** Certificates, private keys, keystores, kubeconfigs.
   Two separable halves, and only the second needs a format change:

   - **Handing a child a path rather than a value.** Many consumers take a
     filename, not an environment variable: `--ssl-ca`, `-i`, `--cacert`. Today
     the caller has to materialize the value itself, which puts plaintext on
     disk and leaves cleanup to whoever wrote the wrapper. See the note below
     on why `execve` makes cleanup the hard part.
   - **Storing bytes the write paths currently refuse.** A PEM file already
     works — it is NUL-free text. DER, PKCS#12 and JKS do not. `Secret` is an
     object precisely so a per-secret encoding can be added without a breaking
     migration, and `Vault.Version` is checked rather than guessed at.

   Whatever the delivery mechanism, it must not defeat the reason `run` uses
   `execve`: nothing is left holding plaintext after the exec, and there is no
   parent to clean up after the child. A path that only exists for the lifetime
   of the process is worth more here than a path on disk with a `defer` behind
   it.

2. **Audit log.** Append-only; log which provider resolved, once providers
   exist.

3. **`edit` verb** via a `$XDG_RUNTIME_DIR` temp file. Editor swap and undo
   files are the footgun — they land next to the temp file and outlive it.

4. **Session lock.** Passphrase-wrapped identity (`age -p`), unwrapped key
   cached in `$XDG_RUNTIME_DIR` with an absolute TTL, `unlock`/`lock` verbs.
   **The only item here that produces an actual boundary**, and it costs
   unattended operation to get it. Promote it the moment unattended operation
   stops being the priority.

5. **Provider abstraction.** `resolve() → age identity`, config-ordered, and
   **never** silently falling through from "configured but locked" to a weaker
   source. KeePassXC via Secret Service is the intended first provider.
