# sudo-policy-diff study 3: host and alias matching — pre-registration

Frozen 2026-11-18, before any run; amendment A1 added 2026-11-19, still before any run.
Munim, Inc. (MV2); made with AI agents working in MV2's name; not yet checked by a human
expert. Licence: CC BY 4.0 (text), Apache-2.0 (code).
Public from 2026-11-19 (see amendment A1).

## 1. Question

Ubuntu 26.04 and 26.10 ship sudo-rs as the default `sudo`, and admins carry their sudoers
files over. Host lists (`alice ALL, !PROD = ...`) and negated aliases are the standard way a
central sudoers file excludes machines or people. Does sudo-rs ever grant on a machine or to
a user that Todd Miller's sudo excludes, because the two match host names and aliases
differently?

## 2. What the source says (read 2026-11-18, re-checked 2026-11-19, sudo-rs `main`, 0.2.15)

sudo-rs (trifectatechfoundation/sudo-rs):
- `src/sudoers/tokens.rs` Hostname: accepts `[A-Za-z0-9.-_]` only; a dotted-quad is refused
  ("hosts cannot be specified using an IPv4 address", PR #1473 for issue #1466). So IPv4
  addresses, `a.b.c.d/nn` networks, IPv6 (`:`), wildcards (`*`) and `+netgroup` are parse
  errors. Issue #230 (closed "not planned", 2025-02-10): sudo-rs matches only "the exact
  hostname you have given your device".
- `src/sudoers/basic_parser.rs` `parse_lines`: a statement that fails is dropped whole (no
  partial alias is kept) and the parser skips to the next newline.
- `src/sudoers/mod.rs` `process`: a Fatal parse error is pushed to diagnostics and the loop
  continues; the bad line contributes nothing.
- `src/sudo/pipeline.rs` `read_sudoers`: diagnostics are printed and `Ok(sudoers)` is returned;
  sudo-rs goes on to judge the request with whatever parsed.
- `find_item`: `Meta::Alias(id) if aliases.contains_key(id)`, else `_ => {}`. So a reference to
  an undefined alias is skipped. `sanitize_alias_table` reports undefined aliases only inside
  other alias definitions, not in user specs.
- `match_token`: `token.as_str() == text`, with `text` = full `gethostname()` (no lowercasing,
  no truncation at the first dot).
- The sudo-rs sudoers(5) page says shell wildcards may be used in host names and calls the
  format "syntax-compatible"; it says nothing about case, short names or IP addresses.

Todd Miller's sudo (sudo-project/sudo `plugins/sudoers/match.c`):
- `host_matches`: NTWKADDR via `addr_matches` (IPv4/IPv6, networks), NETGROUP, ALIAS, WORD.
- `hostname_matches`: pattern with a dot -> compared with the long host, else with the short
  host (host up to the first dot); `strcasecmp`, or `fnmatch(..., FNM_CASEFOLD)` with wildcards.
- An undefined host alias falls through to a literal host-name comparison.

## 3. Cases (fixed, `hostcases.py`)

Invoker alice (in group team); every rule is `(root) NOPASSWD: /usr/local/bin/probe`; request
`sudo -n /usr/local/bin/probe`. `{HOST}` is the container's host name; `{HOSTCASE}` the same
name with its last letter's case flipped (never an alias-shaped name); `{SHORT}` the part
before the first dot.

- H1-H5 `Host_Alias PROD = {HOST}, X` + `alice ALL, !PROD = ...` with X = `10.99.0.0/16`,
  `192.0.2.10`, `2001:db8::/32`, `db-*`, `+prodhosts`. Predicted sudo DENY, sudo-rs ALLOW.
- H6 `User_Alias BLOCKED = alice, +contractors` + `ALL, !BLOCKED ALL = ...`. sudo DENY, rs ALLOW.
- S1 `alice ALL, !{HOSTCASE} = ...`; S2 the same through a Host_Alias. sudo DENY, rs ALLOW.
- F1 `alice ALL, !{SHORT}`; F2 via alias (machine name set to `{HOST}.sudodiff.test`).
  sudo DENY, rs ALLOW. F4 positive `alice {SHORT}`: sudo ALLOW, rs DENY. F3 control.
  F cases are N/A if the container may not call sethostname (expected without CAP_SYS_ADMIN).
- R1 `alice ALL, !10.99.0.0/16 = ...` (whole grant dropped by sudo-rs), R2 positive alias with
  a network, R3 positive `{HOSTCASE}`: sudo ALLOW, rs DENY.
- Controls C1-C7 (exact names, plain aliases, plain user aliases): both agree.
- K1 exploratory: `Cmnd_Alias BLOCKED = /usr/bin/true, ^/usr/local/bin/pro.e$` and
  `alice ALL = (root) NOPASSWD: /usr/local/bin/*, !BLOCKED`. Predicted sudo DENY, rs ALLOW
  only if sudo-rs rejects the regular expression; not part of any hypothesis.

Each case runs twice per implementation (stable = same decisions both times); both visudo
checks and sudo-rs's stderr are recorded.

## 4. Hypotheses (graded automatically by `grade()`; hand triage after)

- **H1** (main): H1 and H6 as predicted and stable: an alias dropped for unsupported syntax
  removes a negated exclusion in sudo-rs. H1_count reports H1-H6.
- **H2**: S1 and S2 as predicted (silent, no diagnostic expected).
- **H3**: F1 and F2 as predicted, or n/a.
- **H4**: R1 and R2 as predicted (fail-closed mirror); H4_count reports R1-R3.
- **H5**: all non-n/a controls agree. If H5 fails, no other result is reported as a finding.
- **H6**: every permissive as-predicted case ran the probe as uid 0.
- Descriptive: for H cases, does sudo-rs print a diagnostic on each run (non-empty stderr)?
  For S/F cases, is stderr empty (silent)?

Preflight (NOPASSWD ALL allowed as uid 0 by both; no rule denied by both) must pass, else the
run is a harness failure, not a result.

## 5. What would count, and what it would mean

If H1/H2/H3 hold: under policies that sudo accepts and enforces, sudo-rs runs the command as
root on machines (or for users) the admin explicitly excluded. H1 is visible on stderr at
every run; H2/H3 are silent.

If they fail: publish the cases and results as a negative result in the open repo.

## A1. Amendment (2026-11-19, before any result): how the maintainers classify this

The sudo-rs maintainers have stated their threat model publicly in closed reports #1619
(2026-05) and #1672 (2026-08): sudoers is "a trusted file" edited only by the admin; "not
every bug (or incompatibility with ogsudo) is a vulnerability: for that, there has to be a
plausible attack scenario"; a parse error that is printed "every time sudo is run" is not a
silent bypass. Both reports (argument restrictions lost after a parse error, with a root
exploit) were closed as `invalid` and published.

Consequences, fixed now so the result cannot steer them:
- This pre-registration is made **public before any result** (it was private until now).
  Every case needs an admin-written sudoers file; no user can create the condition, so
  publishing the predictions puts no machine at risk that is not already misconfigured.
- **H1 (diagnostic printed)** is, by the maintainers' own stated policy, a compatibility bug,
  not a vulnerability. If it holds it is reported as an ordinary public issue with the
  results.
- **H2/H3 (silent)** differ from #1619/#1672 in the one respect the maintainers named: no
  error is shown. If H2 holds, the results are published and the maintainers are told in
  one public issue (or, while MV2 cannot post on GitHub, one short email to the sudo-rs
  security contact pointing at the public results), asking whether they consider a silent
  inversion of a negated host exclusion in scope. H3 rests on source reading alone if the
  F cases are n/a.
- R cases are compatibility notes.
- The study's public value does not depend on the security label: it is the first measured,
  pre-registered comparison of how the two implementations of Ubuntu's default sudo decide
  host- and alias-based policies.
