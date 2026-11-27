#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
#
# Amendment A3: run ONE pre-registered sudo-policy-diff study exactly as it was
# written (a normal user invokes the set-uid sudo binaries; study 3 may set the
# host name), inside a disposable, privileged Ubuntu container on a
# GitHub-hosted runner.
#
#   usage: run-in-container.sh <study1|study2|study3>
#   mounts: /src  this repository (read-only)
#           /out  results (one sub-folder per study)
#
# Never run this on a real machine: the studies rewrite /etc/sudoers, create
# users, set passwords and change the host name.
set -u

study="${1:-}"
case "$study" in
  study1|study2|study3) ;;
  *) echo "usage: $0 <study1|study2|study3>" >&2; exit 2 ;;
esac

if [ ! -f /.dockerenv ] && [ "${SPD_DISPOSABLE:-}" != "1" ]; then
  echo "refusing to run: this does not look like a disposable container" >&2
  exit 3
fi

out="/out/$study"
mkdir -p "$out"

export DEBIAN_FRONTEND=noninteractive
if ! { apt-get update -qq && apt-get install -y -qq --no-install-recommends \
         python3 sudo sudo-rs util-linux passwd; } >"$out/apt.log" 2>&1; then
  echo "apt-get failed"
  tail -n 40 "$out/apt.log"
  echo "exit apt" >"$out/exit.txt"
  exit 1
fi

{
  cat /etc/os-release
  echo "--- packages"
  dpkg-query -W -f '${Package} ${Version}\n' sudo sudo-rs util-linux libc6 libpam-runtime
  echo "--- binaries"
  ls -l /usr/bin/sudo /usr/bin/sudo.ws /usr/bin/sudo-rs /usr/sbin/visudo.ws /usr/bin/visudo-rs
  echo "default sudo resolves to: $(readlink -f /usr/bin/sudo)"
  echo "--- kernel"
  uname -a
  echo "--- process"
  grep -E 'NoNewPrivs|CapEff|Seccomp' /proc/self/status
  echo "hostname: $(hostname)"
} >"$out/platform.txt" 2>&1

w="$(mktemp -d)"
case "$study" in
  study1)
    cp /src/sudodiff.py /src/sudoers_gen.py /src/outcome.py \
       /src/test_outcome.py /src/test_sudoers_gen.py "$w"/
    main=(python3 sudodiff.py --out "$out" --budget-minutes 75)
    ;;
  study2)
    # The study folder's own files win over the root copies.
    cp /src/sudodiff.py /src/sudoers_gen.py /src/outcome.py "$w"/
    cp /src/study2-runas/*.py "$w"/
    main=(python3 runas_cases.py --out "$out" --repeats 2)
    ;;
  study3)
    cp /src/study3-hosts/*.py "$w"/
    main=(python3 hostcases.py --out "$out" --repeats 2)
    ;;
esac

cd "$w" || exit 1
sha256sum ./*.py >"$out/code-sha256.txt"

if ! python3 -m unittest -v >"$out/unittest.log" 2>&1; then
  echo "unit tests failed"
  tail -n 60 "$out/unittest.log"
  echo "exit unittest" >"$out/exit.txt"
  exit 1
fi

"${main[@]}" >"$out/stdout.txt" 2>"$out/stderr.txt"
rc=$?
echo "exit $rc" >"$out/exit.txt"
tail -n 60 "$out/stdout.txt"
exit "$rc"
