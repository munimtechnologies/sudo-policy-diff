# Amendment A2 to studies 2 and 3: observing decisions without set-uid

Written 2026-11-24, **before any result of study 2 or study 3 exists**. It changes
only how each decision is observed. Every case, prediction and grading function
in `study2-runas/PREREG-runas.md` and `study3-hosts/PREREG-hosts.md` stays as
frozen; the runner imports `runas_cases.py` and `hostcases.py` unchanged and calls
their own `grade()` functions.

## Why

Studies 2 and 3 were written for an `ubuntu:26.10` container in which an
unprivileged test user runs the set-uid `sudo` binaries. Two facts about the
compute MV2 has make that impossible:

1. Those jobs (and every other non-Python/Node/R image job) never started
   in the 5-7 days they were queued.
2. Containers there run with `NoNewPrivs: 1` and without `CAP_SYS_ADMIN`
   (seen in another field's job output: `CapEff: 00000000000005fb`). Under
   no-new-privileges a set-uid binary never gains root, so the old preflight
   would have failed. The FQDN cases (F1-F4) need `sethostname`, so they cannot
   run either.

## What changes

`a2-rootmode/rootmode.py` runs on `python:3.12` (Debian), with Todd Miller's
`sudo` from Debian and the **official sudo-rs release binaries** for three
versions: 0.2.13 (Ubuntu 26.04 LTS ships 0.2.13), 0.2.14 (Ubuntu 26.10 ships
0.2.14) and 0.2.15 (latest upstream). Each tarball's SHA-256 is checked against
that release's `SHA256SUMS`, and both are recorded.

Two ways of observing a decision, neither of which needs set-uid:

- **Run mode (primary).** Root is already privileged, so root invokes sudo. Every
  policy line is rewritten with the user names `alice` and `root` swapped, and
  with `#2001` and `#0` swapped. Root is given alice's study-2 groups (`team`,
  `wheel`), and alice gets root's (none). A request that relied on the implicit
  default target (the literal user `root`) names the swapped target (`-u alice`)
  explicitly. Under this renaming every rule means the same thing about the
  invoker as before. The probe really runs and reports its uid, egid and groups.
  Not invariant under the swap, so not run in this mode: study 2 E1 and E2 (no
  Runas spec, so the target is the built-in literal `root`), and study 3 C7
  (the invoker is bob, who cannot invoke without set-uid). The swap-adjusted
  H5 (study 2) expects uid 0 with egid 3500. The swap-adjusted H6 (study 3)
  expects the granted target to be uid 2001, which now plays root.
- **List mode (study 3, cross-check).** Root runs
  `sudo -n -l -U <invoker> -u root /usr/local/bin/probe`. Both implementations
  then judge whether `<invoker>` may run the probe as root on this host. sudo-rs
  calls the same `Sudoers::check` it uses to run a command
  (`src/sudo/pipeline/list.rs`). The decision is ALLOW if the exit status is 0
  and the probe's path is printed. If root is refused permission to list, a
  `root ALL=(ALL:ALL) NOPASSWD: ALL` line is added for the whole run and
  recorded. List mode is not used for study 2: those cases turn on "the target
  is the invoker", and in list mode the invoker is root, not the listed user.

Preflight, per implementation and mode: in run mode, root is allowed by its own
`ALL` rule, denied when only bob has a rule, switches to alice (uid 2001) with
`-u alice` and gets egid 3500 with `-g svcgrp`. In list mode, alice is listed as
allowed by her `ALL` rule and as denied when only bob has a rule. An
implementation that fails its preflight counts as n/a in that mode.

## Grading

The pre-registered hypotheses are graded separately for each combination of
study, mode and sudo-rs version, using the frozen `grade()` functions on the
cases that could run. Run mode is primary. If run mode and list mode disagree for
the same implementation, that is reported, and the case is checked by hand
before it is claimed.

## Limits added by A2

In run mode the invoker is uid 0. Neither implementation's matching code
special-cases root (sudo-rs uses `is_root()` only to skip authentication), but a
divergence found here should still be reproduced as written, with a normal user
on a normal machine, before it goes into an upstream issue. Debian's sudo
(the version is recorded in `env.json`) is not the exact `sudo.ws` build Ubuntu 26.10 ships. Study
1 (random differential) stays queued as written; it needs a normal-user invoker
and is not covered by A2.

MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's name;
not yet checked by a human expert. Text CC BY 4.0, code Apache-2.0.
