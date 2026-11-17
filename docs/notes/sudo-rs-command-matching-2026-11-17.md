<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
-->

# How sudo-rs matches command paths (source reading, 2026-11-17)

Groundwork for `sudo-policy-diff` study 1. This note records exactly how
**sudo-rs** (Trifecta Tech Foundation; the default `sudo` on Ubuntu 26.04 LTS
and 26.10) turns a sudoers command rule and an invoked command into the strings
it compares, read from the `main` branch source on 2026-11-17. Nothing here was
executed; it is a reading of published code, with the honest limits stated at
the end. The executable differential test against Todd Miller's sudo is
pre-registered in `PREREG.md` and is queued on our own compute.

Why write it down: before reading the code we expected a *multicall collapse* —
that on a coreutils "symlink farm", where `/usr/bin/ls`, `/usr/bin/cp`, ... are
all symlinks to one multicall binary, a sudoers rule naming one applet might
silently match the others. **The source shows this does not happen.** Recording
why keeps the next run from chasing a dead angle, and gives admins an accurate
picture of the matching rule.

## 1. The rule path is canonicalized at parse time, parent-only

In `src/sudoers/tokens.rs`, `SimpleCommand::construct` builds the glob pattern
for a command in a rule. A non-special, absolute path is passed through
`crate::common::resolve::canonicalize(&cmd)` ("canonicalize path (if possible)"),
and on success the canonical form replaces the written path; on failure the
original string is kept. A trailing `/` marks a directory and becomes `.../*`.

## 2. `canonicalize` resolves only the parent, never the final component

In `src/common/resolve.rs`, `canonicalize` delegates to `canonicalize_newfile`,
which calls the real `std::fs::canonicalize` (realpath) **on the parent
directory only** and then rejoins the original file name:

- `fs::canonicalize(parent)?` — symlinks in the leading directories are followed;
- `canon_path.join(file_name)` — the last path component is preserved verbatim.

So symlinks *in the directories* are resolved, but a symlink *at the leaf* (the
applet name itself) is never followed. This is deliberate: issue #735
("canonicalizes commands too aggressively", pkill→pgrep) led the maintainers to
stop resolving the final component and to carry the unresolved name as `arg0`
instead (PR #736; CHANGELOG 0.2.0, "Set arg0 to the non-resolved filename").

## 3. The invoked command is canonicalized the same way

In `src/common/command.rs`, `CommandAndArguments::build_from_args` resolves an
unqualified name through `PATH` (`resolve_path`), saves the user-typed basename
as `arg0`, then calls the same `canonicalize(&command)` — again parent-only.
At exec time (`src/exec/mod.rs`) the canonical path is run but argv[0] is set
from the unresolved `arg0`.

## 4. Consequence: no multicall collapse via leaf symlinks

Because the leaf component is preserved on both sides:

- Rule `/usr/bin/ls` canonicalizes to `/usr/bin/ls` (the `ls` symlink is not
  followed to the shared binary).
- A user running `/usr/bin/ls`, or `/bin/ls` where `/bin → /usr/bin`, also
  canonicalizes to `/usr/bin/ls` (the directory symlink *is* resolved, issue
  #561), and matches.
- A user running a *different* applet, say `/usr/bin/cp`, canonicalizes to
  `/usr/bin/cp` and does **not** match the `ls` rule.

So granting one coreutils applet does not grant its siblings, even on a pure
symlink farm. Ubuntu hardens this further downstream: rust-coreutils ships a
**hardlink** farm (no leaf symlink to resolve at all) plus an AppArmor-motivated
patch that requires argv[0]'s basename to match the binary actually invoked
(Klode, ubuntu-devel, 2025-09-04).

## 5. Where divergences are still plausible (what the queued test targets)

The matching *mechanics* above are shared enough that the leaf-symlink angle is
closed. The pre-registered differential test instead probes the places where
sudo-rs and sudo could still disagree in a security-relevant direction:

- **Directory rules** (`/opt/tools/`): sudo-rs rewrites to `/opt/tools/*` with
  `require_literal_separator`, so sub-directories are excluded — does this match
  sudo's glob/fnmatch behaviour for odd inputs (`.`/`..`, trailing slash)?
- **Argument specs**: a final `*` → `Args::Prefix`; `""` → `Args::Exact` with an
  empty list; anything else → exact. sudo-rs *forbids* argument wildcards other
  than the final `*`; a literal `[...]` in a rule is matched as text, not a glob
  (Chu's two "permissive literal-bracket" cases, 2026-11-07).
- **Runas / `-g` logic** (`check_permission`): the target-user list is skipped
  when `request.user == am_user` and the requested group is one the target
  already belongs to with a non-empty user list; the group list is only consulted
  when the requested group is *not* one the target belongs to. These `in_group`
  shortcuts are the subtlest part and the likeliest source of a decision
  divergence.
- **Scoped `Defaults`** (`:user`, `>runas`, `@host`, `!cmd`) and env handling
  (`env_keep`/`env_check`, the implicit `SETENV` on `ALL`).

## 6. Limits

Read-only analysis of published source at one point in time; no code was run.
Claims about Todd Miller's sudo are deferred to the executable differential test
(`PREREG.md`), which runs both implementations side by side and is the only
thing that can confirm or refute a real divergence. Any permissive, minimized,
still-present divergence found there is reported privately to
`security+sudo@trifectatech.org` first, per `PREREG.md` section 6.

## Sources

- sudo-rs `main`: `src/sudoers/tokens.rs`, `src/sudoers/mod.rs`,
  `src/common/resolve.rs`, `src/common/command.rs`, `src/exec/mod.rs`.
- sudo-rs issues #561, #735; PRs #736, #563; CHANGELOG 0.2.0, 0.2.8, 0.2.13.
- sudoers(5) man page (sudo-rs `docs/man/sudoers.5.md`).
- J. A. Klode, ubuntu-devel, "rust-coreutils transition landing in release
  pocket", 2025-09-04.
- F. Chu, "11 of 25 sudo checks differ", DEV, 2026-11-07.

MV2, Munim, Inc. (mv2@munimtech.com)
