# Pre-registration: sudo-policy-diff, study 1

Frozen 2026-11-17, before any data was collected. Author: MV2, Munim, Inc.
(mv2@munimtech.com). Made with AI agents working in MV2's name. Licence: Apache-2.0.

## 1. Question

Ubuntu 26.04 LTS and 26.10 run **sudo-rs** (a Rust rewrite) as their default
`sudo`. Admins carry their existing `/etc/sudoers` files over. **For policies
written in the sudoers subset that sudo-rs documents as supported, does sudo-rs
ever grant MORE than Todd Miller's sudo?** "More" means any of these: it runs a
command sudo refuses; it accepts a weaker password (the invoker's where sudo
demands root's or the target's); it runs the command as a more privileged
uid/gid or with extra groups; it executes a different binary; or it lets a
user-chosen environment value reach the command that sudo removes.

Any such case is a policy-confusion privilege escalation: the admin's file
means one thing and the default sudo enforces another.

## 2. Prior art (checked 2026-11-17)

- sudo-rs's own compliance suite (Ferrous Systems / Trifecta Tech Foundation)
  runs hand-written scenarios against both implementations in Docker. It is an
  executable specification, not a generator of random policies.
- Frank Chu, DEV, 2026-11-07, "11 of 25 sudo checks differ": 25 hand-picked
  list-mode probes (`sudo -l -U`) on sudo-rs 0.2.4 vs sudo 1.9.15p5, without
  executing anything. All 11 differences involved argument wildcards, which
  sudo-rs documents as unsupported. Two were permissive (sudo-rs accepted a
  literal `-bp[acru]` string).
- Chris Siebenmann, 2026-11-02, "The Ubuntu 26.04 Rust sudo is not compatible
  with standard sudo" (compatibility, not security).
- sudo's own fuzzers (fuzz_sudoers, fuzz_policy) look for crashes in one
  implementation, not for differences between two.
- Published sudo-rs advisories (6, 2023-2026): session-file path traversal,
  `-l -U` privilege listing, file-existence leak, partial password echo,
  timestamp user recording, and the sudoedit TOCTOU (USN-8708). None comes
  from a policy-semantics difference.

We found no random, execution-based differential test of sudoers policy
semantics between the two. That is what this study adds.

## 3. Method

- **Environment:** a disposable `ubuntu:26.10` container, with Ubuntu's `sudo`
  package (`/usr/bin/sudo.ws`) and `sudo-rs` package (`/usr/bin/sudo-rs`)
  installed side by side. Versions are recorded in `env.json`.
- **Users:** test users alice, bob, carol and svc, and groups team, wheel, ops
  and svcgrp, with fixed uids and gids. Throwaway random passwords are made at
  start-up, held only in memory and never written out. pam_unix gets `nodelay`
  so wrong passwords cost no time.
- **Probes:** five root-owned probe programs and per-user symlinks. Each user
  also owns an "evil" probe in their own home. A probe prints its tag, the
  executed path, argv, uid/euid/gid/egid, groups, cwd, umask and environment.
- **Policies:** `sudoers_gen.py` draws random policies from the grammar both
  man pages document: aliases; negation; `#uid`, `%group` and `%#gid`; Runas
  forms `(u)`, `(u:g)`, `(:g)` and `()`; the tags NOPASSWD, PASSWD, SETENV,
  NOSETENV and EXEC; `CWD=`; directory and glob command paths; argument specs
  (none, `""`, exact, or a final `*`); and scoped Defaults (`env_keep`,
  `env_check`, `setenv`, `secure_path`, `rootpw`, `targetpw`, `umask`,
  `umask_override`, `runcwd`). Every policy starts with
  `Defaults timestamp_timeout=0`, so cached credentials never carry over
  between attempts.
- **Excluded by construction:** wildcards in arguments (other than a final
  `*`), NOEXEC, INTERCEPT, sudoedit, digests, `env_delete`, regular
  expressions and LDAP.
- **Requests:** each policy gets 12 random requests: an invoker; `-u`/`-g`
  (including `#uid` forms); command forms that include non-canonical paths,
  user-owned symlinks, bare names found through PATH, and relative paths;
  arguments; user environment variables, including LD_PRELOAD, PATH, HOME,
  TZ, BASH_ENV and function-like values; command-line `VAR=value`; `-E`; and
  `-D`.
- **Decision oracle:** each implementation is run as the invoker through
  `setpriv`, first with `-n`, then with `-S` and the invoker's password, then
  root's, then the target's. The first stage that runs the probe decides the
  outcome: ALLOW_NOPASSWD, ALLOW_PW_INVOKER, ALLOW_PW_ROOT or
  ALLOW_PW_TARGET. If no stage runs it, the outcome is DENY.
- **Comparison (`outcome.py`):** DECISION, AUTH, IDENTITY, GROUPS, EXEC, ARGV,
  CWD, UMASK and ENV, each with a direction (permissive, restrictive or
  unclear). Pre-declared as non-security: ENV_BASELINE (built-in default
  variables that the user did not set), ENV_BENIGN (TERM, LANG, LANGUAGE,
  COLORTERM) and EXEC_PATH (same program reached by a different path, such as
  `/dev/fd/N`).
- **Control:** the first 300 requests are run through sudo twice, and the two
  sudo runs are compared with each other.
- **Minimizing:** each distinct permissive or unclear finding (kind,
  direction, detail and request shape; at most 25) is reduced by line-removal
  delta debugging of the policy and by dropping parts of the request. It is
  then re-run twice to confirm it is stable.
- **Settings:** seed 20261117, a 75-minute budget, 1 CPU and 1 GB.

## 4. Predictions (probabilities set before data)

| # | Prediction | P |
|---|---|---|
| P1 | The sudo-vs-sudo control shows 0 differences in its first 300 requests | 85% |
| P2 | Preflight works: both setuid binaries run in the container (NOPASSWD gives uid 0, password works, no rule means DENY) | 75% |
| P3 | At least one DECISION or AUTH divergence of any direction | 90% |
| P4 | At least one permissive DECISION or AUTH divergence outside the excluded classes, still present after minimizing | 30% |
| P5 | At least one permissive ENV divergence on a variable the user chose | 35% |
| P6 | At least one IDENTITY or GROUPS divergence when both allow the command | 30% |
| P7 | visudo-rs rejects at least 5% of the generated policies that visudo.ws accepts | 40% |

`outcome.grade()` prints raw automatic grades. The final grades are written by
hand after triage (section 6) and published together with the raw numbers.

## 5. What would count as a result

- **The "wow":** a minimized, stable sudoers policy inside sudo-rs's documented
  subset where sudo-rs, the default sudo of Ubuntu 26.04/26.10, grants more
  than sudo does. It must also not be a documented difference, must still
  happen on sudo-rs main, and must work for a realistic admin policy.
- **An honest negative:** "N random policies and M requests, 0 permissive
  divergences" bounds the risk for this subset and is published as such.

## 6. Triage and disclosure (decided now)

1. Re-check each permissive finding by hand in a fresh container. Write a
   threat model (attacker = the invoking user; trust boundary = the policy
   the admin wrote).
2. Check the sudo-rs and sudo documentation, and sudo-rs issues and commits
   after the shipped version, so that documented or already-fixed differences
   are labelled as such, not reported.
3. Real security findings go **privately** to security+sudo@trifectatech.org,
   as sudo-rs's SECURITY.md asks, and to sudo's own policy if sudo is also
   affected. They are never sent as a public issue and never published here
   until the maintainers have released a fix or agreed to disclosure.
   Compatibility-only (restrictive) differences may be reported publicly,
   a few at a time.
4. The results note in this repository follows disclosure.
