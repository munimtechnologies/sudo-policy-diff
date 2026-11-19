# sudo-policy-diff

Does **sudo-rs**, the default `sudo` on Ubuntu 26.04 LTS and 26.10, enforce
your `/etc/sudoers` the same way Todd Miller's sudo does?

sudo-policy-diff is a differential tester for that question. It generates
random sudoers policies inside the subset that both implementations document,
and random requests to go with them: who runs it, `-u`/`-g`, the command form,
arguments, the user's environment, `VAR=value` on the command line, `-E` and
`-D`. It **runs** every request through both implementations in a disposable
Ubuntu 26.10 container, then compares the results: whether the command ran,
which password was accepted, which uid/gid/groups it ran as, which binary was
executed, and which of the user's environment values reached it. Any case
where sudo-rs grants more than sudo is minimized into a small reproducer.

- Method and predictions, frozen before any data: [PREREG.md](PREREG.md)
- Generator (pure, deterministic): `sudoers_gen.py`
- Classifier (pure): `outcome.py`
- Container runner: `sudodiff.py` (run it only as root in a throwaway
  container; it rewrites `/etc/sudoers` and creates users)

```sh
# inside ubuntu:26.10, as root
apt-get update && apt-get install -y python3 sudo sudo-rs
python3 -m unittest -v
python3 sudodiff.py --out ./out --budget-minutes 75
```

Outputs: `env.json` (versions, preflight), `cases.jsonl` (every request),
`findings.json` (minimized reproducers), `summary.json` and `summary.md`.

## Studies

| study | question | cases | status |
|---|---|---|---|
| 1 (root folder) | random differential over the shared sudoers subset | random, seed 20261117 | pre-registered, queued |
| [2 `study2-runas/`](study2-runas/PREREG-runas.md) | are negated Runas entries honoured with `-g`? | 26 fixed | pre-registered, queued |
| [3 `study3-hosts/`](study3-hosts/PREREG-hosts.md) | do host lists and aliases match the same machines? | 23 fixed | pre-registered, queued |

Studies 2 and 3 come from reading both implementations' source. Each
prediction cites the function it rests on. Study 3 predicts two kinds of
difference:

- A `Host_Alias` or `User_Alias` that uses syntax sudo supports but sudo-rs
  rejects (IP address or network, wildcard, `+netgroup`) is dropped by sudo-rs
  with a printed error, and a **negated** reference to it (`ALL, !PROD`) then
  excludes nothing.
- sudo compares host names without regard to case, and compares a dot-less
  pattern with the short host name. sudo-rs compares the exact full host name.
  So a negated host such as `!DB1`, or `!db1` on a machine named
  `db1.example.com`, may stop excluding that machine, with no message at all.

The sudo-rs maintainers treat sudoers as a trusted, admin-written file. Their
closed reports [#1619](https://github.com/trifectatechfoundation/sudo-rs/issues/1619)
and [#1672](https://github.com/trifectatechfoundation/sudo-rs/issues/1672) say
that an incompatibility is not a vulnerability unless it comes with a plausible
attack scenario. Every case here needs an admin-written policy, so the
pre-registrations are public before any result, and results will be reported
to sudo-rs as public compatibility issues (see each PREREG's amendment A1).

A source-reading note that ruled out one suspected divergence (symlinked
multicall binaries) is in [docs/notes](docs/notes/sudo-rs-command-matching-2026-11-17.md).

## Related work

The sudo-rs compliance test suite (Ferrous Systems, Trifecta Tech Foundation);
Frank Chu's 25 list-mode checks on sudo-rs 0.2.4 (DEV, 2026-11-07); Chris
Siebenmann's compatibility notes (2026-11-02); and sudo's own fuzzers. See
PREREG.md section 2. sudo-rs issues #230 (exact host-name matching, closed not
planned), #1466 (IP addresses) and #1468 (negated hosts in `Defaults@`).

## Credits and licence

By MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's
name; not yet checked by a human expert. Code is licensed under Apache-2.0;
the pre-registration texts may also be used under CC BY 4.0.
