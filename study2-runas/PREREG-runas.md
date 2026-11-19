# Pre-registration: sudo-policy-diff, study 2 (Runas negation)

Frozen 2026-11-17 (about 17:00 UTC), before any data from this study or from study 1
existed; amendment A1 added 2026-11-19, still before any data. Author: MV2, Munim, Inc.
(mv2@munimtech.com). Made with AI agents working in MV2's name; not yet checked by a human
expert. Licence: Apache-2.0 (code), CC BY 4.0 (this text). Public from 2026-11-19.

## 1. Question

Ubuntu 26.04 LTS and 26.10 ship **sudo-rs** as the default `sudo`. Does sudo-rs honour
negated entries (`!name`, `!%group`, `!#uid`, negating `Runas_Alias`) in a Runas_Spec the
way Todd Miller's sudo does, when the request uses `-g`?

The last time a Runas negation was ignored, it was CVE-2019-14287 (`(ALL, !root)`
bypassed with `-u#-1`). The sudo-rs compliance suite has one Runas negation test (that
CVE) and three Runas_Alias negation tests, all without `-g`. None negates anything in
the group list.

## 2. Where the predictions come from (source reading, not yet run)

**sudo-rs** (`src/sudoers/mod.rs`, `check_permission`, main branch, 2026-11-17):

```
stays_in_group = in_group(request.user, request.group)
if request.user != am_user || (stays_in_group && !users.is_empty()):  check user list
if !stays_in_group:                                                   check group list
```

So the user list is never consulted when you run as yourself with a group you are not
in. The group list is never consulted when the target user is already in the group.

**sudo** (`plugins/sudoers/match.c`, `runaslist_matches`, main): the user list is always
walked (last match wins, a matching negated entry is DENY). The group list is walked
whenever `-g` is given, and a matching negated group is DENY. Only an UNSPEC result
falls back to "the target user's own groups". A DENY on either side denies. A "sudo -g
group" rescue turns user UNSPEC into ALLOW only if the group matched and the runas user
is the invoker.

## 3. Method

A disposable `ubuntu:26.10` container runs the Ubuntu `sudo` (`/usr/bin/sudo.ws`) and
`sudo-rs` (`/usr/bin/sudo-rs`) packages side by side. It reuses the study-1 harness
(`sudodiff.py`): the same users, probes, setpriv invocation and preflight. There are 26
fixed cases in `runas_cases.py`, each with a one-line NOPASSWD rule for alice (alice is
in team and wheel, bob in team; svcgrp is svc's primary group). Each case runs twice; it
is stable if both runs agree. The outcome classes are ALLOW (any stage ran the probe)
and DENY.

- **Family A** (6 divergence cases, 4 controls): run as yourself with `-g svcgrp`
  while the user list negates you (`!alice`, `!%wheel`, `!#2001`, negating
  Runas_Alias, `-u alice` explicitly, negation-only list). Predicted: sudo DENY,
  sudo-rs ALLOW.
- **Family B** (3 divergence cases, 3 controls): the target is already in the
  requested group, and the group list negates that group. Predicted: sudo DENY,
  sudo-rs ALLOW.
- **Family C** (2 divergence cases, 2 controls): run as yourself with `-g` of a
  group you are in. The group is listed, but you are not in the user list.
  Predicted: sudo ALLOW, sudo-rs DENY (restrictive).
- **Families D/E** (6 controls): `()`, `(:g)` and no Runas_Spec. Predicted: both
  implementations agree.

## 4. Predictions (probabilities set before data)

| # | Hypothesis | P |
|---|---|---|
| H1 | All 6 family-A divergence cases: sudo DENY, sudo-rs ALLOW, stable | 70% |
| H2 | All 3 family-B divergence cases: sudo DENY, sudo-rs ALLOW, stable | 70% |
| H3 | Both family-C cases: sudo ALLOW, sudo-rs DENY, stable | 70% |
| H4 | Every control gives the same ALLOW/DENY class in both | 75% |
| H5 | Where sudo-rs allows an A case, the probe runs as uid 2001 (alice) with egid 3500 (svcgrp), never as root | 90% |

## 5. What it would mean

- **Impact, stated before data.** Family A lets a user combine their own uid with a
  group that the admin listed for other targets, after the admin explicitly excluded
  them. That is a real permissive policy divergence, but its reach is bounded: it never
  yields root or another user's uid. Family B changes only which of the target's own
  groups is the primary gid. That is a compatibility difference, not a privilege gain.
- **If H1 fails:** the source reading was wrong somewhere (for example in how
  `request.user != am_user` compares users). That is published as an honest negative,
  along with which line of reasoning failed.
- Results also need to be checked against sudo-rs main, because the container tests
  the Ubuntu 26.10 package version.

## A1. Amendment (2026-11-19, before any data): disclosure route

The original plan sent a confirmed H1 privately to the sudo-rs security contact first.
Since then we read the maintainers' published threat model (closed reports #1619 and
#1672, both labelled `invalid`): sudoers is a trusted, admin-written file, and "not every
bug (or incompatibility with ogsudo) is a vulnerability: for that, there has to be a
plausible attack scenario". Family A needs the admin to write a negated Runas entry, and
in most rule shapes (`(ALL, !alice : svcgrp)`) the same rule already lets alice run as
other users with svcgrp, so the extra gain is small. Only the negation-only shape (A6,
`(!alice : svcgrp)`) gives a group the rule never granted to anyone.

So, fixed now: this pre-registration is public from 2026-11-19; whatever the result, it
is published with the run output and reported to sudo-rs as an ordinary public
compatibility issue, with A6 named as the one shape that gains a group. No embargo.

The same run also re-runs study 1 (`sudodiff.py`, random differential, seed 20261117,
60-minute budget) into a separate output folder, unchanged from its own pre-registration.
