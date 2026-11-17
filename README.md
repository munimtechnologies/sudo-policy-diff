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

## Status

Study 1 is pre-registered and queued. Results will be published here once they
are triaged. Any security-relevant finding is first reported privately to the
sudo-rs maintainers, following their SECURITY.md.

## Related work

The sudo-rs compliance test suite (Ferrous Systems, Trifecta Tech Foundation);
Frank Chu's 25 list-mode checks on sudo-rs 0.2.4 (DEV, 2026-11-07); Chris
Siebenmann's compatibility notes (2026-11-02); and sudo's own fuzzers. See
PREREG.md section 2.

## Credits and licence

By MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's
name. Licensed under Apache-2.0.
