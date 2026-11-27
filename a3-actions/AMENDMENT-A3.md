# Amendment A3 to studies 1, 2 and 3: where they run

Written 2026-11-27, **before any result of study 1, 2 or 3 exists**. It changes
only where the studies are executed. Every case, request generator, seed,
prediction and grading function stays as frozen in `PREREG.md`,
`study2-runas/PREREG-runas.md` and `study3-hosts/PREREG-hosts.md`. The runners
are the original ones (`sudodiff.py`, `runas_cases.py`, `hostcases.py`),
unchanged.

## A correction to amendment A2

A2 said the `ubuntu:26.10` jobs never started because of their image. That was
wrong. MV2's job queue records show the real reason: every one of these jobs,
including A2's own `python:3.12` job, was waiting with the reason "research jobs
go first". The shared machines had less free memory than a job's reserve, so
jobs from the priority research fields went first, and the open-source jobs
waited 3 to 10 days without starting. A2's second reason still holds: those
containers run with `NoNewPrivs: 1` and without `CAP_SYS_ADMIN`, so the set-uid
design cannot run there.

## What changes

The studies run on GitHub-hosted runners (`ubuntu-24.04` virtual machines),
each study in its own new, privileged container from the official Ubuntu
images, for **Ubuntu 26.04 LTS and Ubuntu 26.10**:

- `ci/run-in-container.sh <study>` installs `sudo` and `sudo-rs` from the Ubuntu
  archive, records the versions, which binary `/usr/bin/sudo` resolves to and
  the process's `NoNewPrivs`/`CapEff`, runs the study's unit tests, then runs
  the study exactly as pre-registered (study 1: `--budget-minutes 75`, seed
  20261117; studies 2 and 3: `--repeats 2`).
- In a privileged container, set-uid works and the host name can be set, so a
  normal user invokes sudo as designed, and study 3's FQDN cases (F1-F4) can
  run. No case is marked not applicable for lack of privileges.
- The workflow (`ci/studies.workflow.yml`, enabled by copying it to
  `.github/workflows/studies.yml`) commits every output to
  `results/actions/<UTC stamp>/ubuntu-<version>/<study>/`, with a link to the
  public Actions run.

The A2 runner (root invoker with swapped names, list mode, three upstream
sudo-rs release binaries on Debian) stays as a second, independent check. If
A2 and A3 disagree for the same case and version, both are reported and the
case is checked by hand before it is claimed.

## Grading

Each study is graded with its own frozen `grade()` (studies 2 and 3) or by
`PREREG.md` sections 4 and 5 (study 1), separately for Ubuntu 26.04 LTS and
26.10. A3 runs are primary because they match the pre-registered design. A
run that fails its preflight is reported as failed, not graded.

## Limits added by A3

The container runs on a GitHub-hosted virtual machine, not on a physical Ubuntu
install. Its kernel is the runner's, not Ubuntu 26.04's or 26.10's. Both sudo
implementations make their policy decisions in user space, so this should not
change a decision, but the kernel version is recorded and any divergence will
be reproduced on a stock Ubuntu machine before an upstream report.

MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's name;
not yet checked by a human expert. Text CC BY 4.0, code Apache-2.0.
