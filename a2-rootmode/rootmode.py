#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""sudo-policy-diff, amendment A2 runner for studies 2 (Runas) and 3 (hosts).

Why this exists: the compute runner MV2 has gives every container
NoNewPrivs=1 (and no CAP_SYS_ADMIN), so a set-uid sudo started by a normal
user can never become root there, and the ubuntu:26.10 image never ran.
Studies 2 and 3 therefore cannot be run as written. A2 keeps every case,
prediction and grading function and changes only HOW a decision is observed:

  run mode   The invoking user is root (already privileged, so no set-uid is
             needed) and the policy is rewritten with the names alice <-> root
             and #2001 <-> #0 swapped; root gets alice's groups (team, wheel).
             Requests that relied on the default Runas user (the literal
             "root") name the swapped user explicitly. sudo really executes a
             probe that reports uid/gid/egid/groups.
  list mode  `sudo -n -l -U <invoker> -u root [cmd]` run by root: both
             implementations judge whether <invoker> may run the command
             (sudo-rs calls the same Sudoers::check as for running).
             Used for study 3 only (study 2 depends on "the invoker is the
             target", which list mode cannot express).

Implementations: Todd Miller's sudo from Debian, and the official sudo-rs
release binaries 0.2.13 (Ubuntu 26.04 LTS), 0.2.14 (Ubuntu 26.10) and 0.2.15
(latest), unpacked under /opt/sudo-rs/<version>/.

Runs INSIDE a disposable container as root, never on a real machine.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(HERE, "..", "study3-hosts"), os.path.join(HERE, "..", "study2-runas")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hostcases as HC  # noqa: E402  (study 3, unchanged)
import runas_cases as RC  # noqa: E402  (study 2, unchanged)

VERSION = "a2-0.1.0"
PROBE = "/usr/local/bin/probe"
PROBE_PREFIX = "SUDODIFF-PROBE "
SUDOERS = "/etc/sudoers"
HEADER = ("# sudo-policy-diff amendment A2 policy", "Defaults timestamp_timeout=0")
ROOTLINE = "root ALL=(ALL:ALL) NOPASSWD: ALL"
ALLOW, DENY, NA = "ALLOW", "DENY", "N/A"
WS_BIN, WS_VISUDO = "/usr/bin/sudo", "/usr/sbin/visudo"
RS_ROOT = "/opt/sudo-rs"

GROUPS = (("team", 3001), ("wheel", 3002), ("ops", 3003), ("svcgrp", 3500))
# name, uid, primary group (created with gid = uid when None), supplementary groups.
# alice has NO supplementary groups: in run mode she plays root's part, and root
# (who plays alice) gets alice's study-2 groups team and wheel.
USERS = (("alice", 2001, None, ()), ("bob", 2002, None, ("team",)),
         ("carol", 2003, None, ()), ("svc", 2500, "svcgrp", ()))
ROOT_EXTRA_GROUPS = ("team", "wheel")
SELF_UID_SWAPPED, SVCGRP_GID, ALICE_UID = 0, 3500, 2001

# Cases that are NOT invariant under the swap, because their meaning depends on
# the built-in default Runas user, which is the literal name "root".
RUN_MODE_NA = {
    "E1": "no Runas spec: the implicit default target is the literal root, so after "
          "the swap it becomes the invoker itself",
    "E2": "no Runas spec, -u root -g root: same reason as E1",
}

# ------------------------------------------------------------------ pure part

_SWAP = {"alice": "root", "root": "alice", "#2001": "#0", "#0": "#2001"}
_TOK = re.compile(r"(?<![\w#%/.-])(#2001|#0|alice|root)(?![\w-])")


def swap_text(s):
    """Swap alice<->root and #2001<->#0 as whole sudoers tokens."""
    return _TOK.sub(lambda m: _SWAP[m.group(1)], s)


def swap_name(name):
    if name is None:
        return None
    return _SWAP.get(name, name)


def swap_request(req):
    """Run-mode request for a case whose invoker is alice (None if impossible)."""
    if req.get("invoker", "alice") != "alice":
        return None
    u, g = req.get("runas_user"), req.get("runas_group")
    out = {"invoker": "root", "runas_user": swap_name(u),
           "runas_group": swap_name(g) if g in ("alice", "root") else g}
    if u is None and g is None:
        # default target was the literal root (not the invoker); name its swap
        out["runas_user"] = "alice"
    return out


def unify_cases():
    """All study 2 + study 3 cases as one list of plain dicts."""
    out = []
    for c in HC.CASES:
        out.append({"study": "hosts", "id": c["id"], "family": c["family"], "kind": c["kind"],
                    "lines": list(c["lines"]), "needs": c["needs"], "why": c["why"],
                    "expect_ws": c["expect_ws"], "expect_rs": c["expect_rs"],
                    "request": {"invoker": c["invoker"], "runas_user": None,
                                "runas_group": None}})
    for c in RC.CASES:
        rq = c["request"]
        out.append({"study": "runas", "id": c["id"], "family": c["family"], "kind": c["kind"],
                    "lines": list(c["lines"]), "needs": None, "why": c["why"],
                    "expect_ws": c["expect_ws"], "expect_rs": c["expect_rs"],
                    "request": {"invoker": rq["invoker"], "runas_user": rq["runas_user"],
                                "runas_group": rq["runas_group"]}})
    return out


def run_mode_plan(case):
    """(lines, request) for run mode, or (None, reason)."""
    if case["study"] == "runas" and case["id"] in RUN_MODE_NA:
        return None, RUN_MODE_NA[case["id"]]
    rq = swap_request(case["request"])
    if rq is None:
        return None, "invoker is not alice; only root can invoke without set-uid"
    return [swap_text(l) for l in case["lines"]], rq


def run_argv(binary, rq):
    argv = [binary, "-n"]
    if rq.get("runas_user"):
        argv += ["-u", rq["runas_user"]]
    if rq.get("runas_group"):
        argv += ["-g", rq["runas_group"]]
    return argv + [PROBE]


def list_argv(binary, rq):
    argv = [binary, "-n", "-l", "-U", rq["invoker"], "-u", rq.get("runas_user") or "root"]
    if rq.get("runas_group"):
        argv += ["-g", rq["runas_group"]]
    return argv + [PROBE]


def parse_probe(stdout):
    for line in (stdout or "").splitlines():
        if line.startswith(PROBE_PREFIX):
            try:
                rec = json.loads(line[len(PROBE_PREFIX):])
            except ValueError:
                return None
            return rec if isinstance(rec, dict) else None
    return None


def list_decision(rc, stdout):
    """List mode with a command prints the command's path and exits 0 iff allowed."""
    if rc == 0 and any(l.strip().split(" ")[0].endswith(PROBE) for l in (stdout or "").splitlines()
                       if l.strip()):
        return ALLOW
    return DENY


def render(lines, host, hostcase, rootline=False):
    body = ([ROOTLINE] if rootline else []) + list(lines)
    text = "\n".join(list(HEADER) + body) + "\n"
    text = text.replace("{HOSTCASE}", hostcase or "NO_CASE_VARIANT")
    text = text.replace("{SHORT}", HC.short_of(host))
    return text.replace("{HOST}", host)


def legacy(case, ws, rs, stable, verdict):
    """A result in the format the pre-registered grade() functions read."""
    x = {"id": case["id"], "family": case["family"], "kind": case["kind"],
         "lines": case["lines"], "expect_ws": case["expect_ws"], "expect_rs": case["expect_rs"],
         "invoker": case["request"]["invoker"], "request": case["request"], "why": case["why"],
         "needs": case["needs"]}
    x.update({"ws": ws, "rs": rs, "stable": stable, "verdict": verdict})
    return x


def judge(case, w, r):
    if NA in (w, r):
        return "n/a"
    return HC.judge(case, w, r)


def grade_hosts(results, mode):
    g = HC.grade(results)
    perm = [x for x in results if x["kind"] == "divergence" and x["expect_rs"] == ALLOW
            and x["verdict"] == "as_predicted"]
    if mode == "run":
        # swap-adjusted H6: the granted target is the swapped "root", i.e. alice
        g["H6_gain_is_root"] = bool(perm) and all(
            (x["rs"].get("probe") or {}).get("uid") == ALICE_UID for x in perm)
        g["H6_note"] = "swap-adjusted: target uid %d plays root" % ALICE_UID
    else:
        g["H6_gain_is_root"] = "n/a (list mode runs nothing)"
    return g


def grade_runas(results):
    usable = [x for x in results if x["verdict"] != "n/a"]
    g = RC.grade(usable)
    a_allowed = [x for x in usable if x["family"] == "A" and x["kind"] == "divergence"
                 and RC.cls(x["rs"]["decision"]) == ALLOW]
    g["H5_A_gain_is_self_uid_with_group"] = bool(a_allowed) and all(
        (x["rs"].get("probe") or {}).get("uid") == SELF_UID_SWAPPED
        and (x["rs"].get("probe") or {}).get("egid") == SVCGRP_GID for x in a_allowed)
    g["H5_note"] = "swap-adjusted: the invoker is uid %d" % SELF_UID_SWAPPED
    g["not_run"] = sorted(x["id"] for x in results if x["verdict"] == "n/a")
    return g


def summarize(records, rs_versions):
    """Grades per (study, mode, sudo-rs version) from per-case records."""
    out = {}
    for study, modes in (("hosts", ("run", "list")), ("runas", ("run",))):
        for mode in modes:
            for v in rs_versions:
                res = []
                for rec in records:
                    if rec["study"] != study:
                        continue
                    m = rec["modes"].get(mode)
                    if not m or m.get("na"):
                        why = (m or {}).get("na", "not run")
                        na = {"decision": NA, "probe": None, "err": why}
                        res.append(legacy(rec, na, na, True, "n/a"))
                        continue
                    ws, rs = m["impl"]["ws"], m["impl"].get("rs-" + v)
                    if rs is None or ws.get("decision") == NA or rs.get("decision") == NA:
                        na = {"decision": NA, "probe": None, "err": "implementation unavailable"}
                        res.append(legacy(rec, ws or na, rs or na, True, "n/a"))
                        continue
                    stable = ws["stable"] and rs["stable"]
                    res.append(legacy(rec, ws, rs, stable,
                                      judge(rec, ws["decision"], rs["decision"])))
                key = "%s/%s/sudo-rs-%s" % (study, mode, v)
                out[key] = grade_hosts(res, mode) if study == "hosts" else grade_runas(res)
    return out


def agreement(records, rs_versions):
    """Run mode vs list mode, per implementation, where both exist (study 3)."""
    same = diff = 0
    diffs = []
    for rec in records:
        r, l = rec["modes"].get("run"), rec["modes"].get("list")
        if not r or not l or r.get("na") or l.get("na"):
            continue
        for k in ["ws"] + ["rs-" + v for v in rs_versions]:
            a, b = r["impl"].get(k), l["impl"].get(k)
            if not a or not b or NA in (a["decision"], b["decision"]):
                continue
            if a["decision"] == b["decision"]:
                same += 1
            else:
                diff += 1
                diffs.append("%s %s run=%s list=%s" % (rec["id"], k, a["decision"], b["decision"]))
    return {"same": same, "differ": diff, "differences": diffs}


def render_md(env, records, grades, agree, rs_versions):
    impls = ["ws"] + ["rs-" + v for v in rs_versions]
    L = ["# sudo-policy-diff studies 2 and 3, amendment A2 (run as root with swapped names;"
         " list mode)", "",
         "sudo (Todd Miller): `%s`" % env.get("ws_version", "?"),
         "sudo-rs: %s" % ", ".join("`%s`" % env.get("rs", {}).get(v, {}).get("version", "?")
                                   for v in rs_versions),
         "host name: `%s`; case variant: `%s`; fqdn: %s" % (
             env.get("hostname"), env.get("hostcase"), env.get("fqdn_host")), ""]
    for study in ("hosts", "runas"):
        L += ["## %s" % ("Study 3: hosts and aliases" if study == "hosts" else
                          "Study 2: Runas negation"), "",
              "| id | kind | policy (as written) | mode | " + " | ".join(impls) +
              " | predicted sudo/sudo-rs |",
              "|---|---|---|---|" + "---|" * len(impls) + "---|"]
        for rec in records:
            if rec["study"] != study:
                continue
            for mode in ("run", "list"):
                m = rec["modes"].get(mode)
                if m is None:
                    continue
                if m.get("na"):
                    cells = ["n/a"] * len(impls)
                else:
                    cells = []
                    for k in impls:
                        d = m["impl"].get(k)
                        cells.append("-" if d is None else d["decision"] +
                                     ("" if d["stable"] else " (unstable)"))
                L.append("| %s | %s | `%s` | %s | %s | %s/%s |" % (
                    rec["id"], rec["kind"], " ; ".join(rec["lines"]).replace("|", "/"), mode,
                    " | ".join(cells), rec["expect_ws"], rec["expect_rs"]))
        L.append("")
    L += ["## Pre-registered hypotheses (raw, per study / mode / sudo-rs version)", ""]
    for k, v in grades.items():
        L.append("- **%s**: %s" % (k, json.dumps(v, sort_keys=True)))
    L += ["", "## Run mode vs list mode (study 3)", "", json.dumps(agree, sort_keys=True), ""]
    return "\n".join(L) + "\n"


# ------------------------------------------------------------- container I/O

def run(cmd, timeout=30, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("errors", "replace")
    if "input" not in kw:
        kw.setdefault("stdin", subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "TIMEOUT")
    except OSError as e:
        return subprocess.CompletedProcess(cmd, 127, "", repr(e))


def must(r, what):
    if r.returncode != 0:
        raise RuntimeError("%s failed (%s): %s" % (what, r.returncode, (r.stderr or "")[-400:]))
    return r


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True, default=str)
    os.replace(tmp, path)


def probe_script():
    return (
        "#!%s -I\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "import json, os, sys\n"
        "rec = {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),\n"
        "       'egid': os.getegid(), 'groups': sorted(os.getgroups()), 'argv': sys.argv[1:]}\n"
        "sys.stdout.write(%r + json.dumps(rec, sort_keys=True) + '\\n')\n"
    ) % (sys.executable, PROBE_PREFIX)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_file(root, name):
    for d, _dirs, files in os.walk(root):
        if name in files:
            p = os.path.join(d, name)
            if os.path.isfile(p) and not os.path.islink(p):
                return p
    return None


def discover_rs():
    """{version: {sudo, visudo, version, tarball_sha256, sums_match}}"""
    out = {}
    if not os.path.isdir(RS_ROOT):
        return out
    for v in sorted(os.listdir(RS_ROOT)):
        d = os.path.join(RS_ROOT, v)
        info = {"sudo": find_file(d, "sudo"), "visudo": find_file(d, "visudo")}
        tb = os.path.join(d, "sudo-%s.tar.gz" % v)
        if os.path.exists(tb):
            info["tarball_sha256"] = sha256(tb)
            try:
                with open(os.path.join(d, "SHA256SUMS")) as f:
                    sums = f.read()
                info["sums_match"] = info["tarball_sha256"] in sums and ("sudo-%s.tar.gz" % v) in sums
            except OSError:
                info["sums_match"] = "no SHA256SUMS"
        if info["sudo"]:
            os.chown(info["sudo"], 0, 0)
            os.chmod(info["sudo"], 0o4755)
            r = run([info["sudo"], "-V"])
            info["version"] = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[:1]
            info["version"] = info["version"][0] if info["version"] else "?"
        out[v] = info
    return out


def setup():
    info = {"runner": VERSION}
    for name, gid in GROUPS:
        if run(["getent", "group", name]).returncode != 0:
            must(run(["groupadd", "-g", str(gid), name]), "groupadd " + name)
    for name, uid, prim, extra in USERS:
        if run(["getent", "passwd", name]).returncode == 0:
            continue
        if prim is None:
            if run(["getent", "group", name]).returncode != 0:
                must(run(["groupadd", "-g", str(uid), name]), "groupadd " + name)
            prim = name
        cmd = ["useradd", "-m", "-u", str(uid), "-g", prim, "-s", "/bin/sh"]
        if extra:
            cmd += ["-G", ",".join(extra)]
        must(run(cmd + [name]), "useradd " + name)
    must(run(["usermod", "-a", "-G", ",".join(ROOT_EXTRA_GROUPS), "root"]), "usermod root")
    os.makedirs(os.path.dirname(PROBE), exist_ok=True)
    with open(PROBE, "w") as f:
        f.write(probe_script())
    os.chmod(PROBE, 0o755)
    os.chown(PROBE, 0, 0)
    for p in ("/etc/sudoers-rs",):
        if os.path.lexists(p):
            os.unlink(p)
            info["removed"] = p
    host = socket.gethostname()
    info["hostname"] = host
    info["hosts_error"] = HC.add_hosts_entry(host)
    info["hostcase"] = HC.flip_case(host)
    r = run(["dpkg-query", "-W", "-f", "${Package} ${Version}\n", "sudo", "util-linux", "libc6",
             "libpam-runtime"])
    info["dpkg"] = r.stdout
    r = run([WS_BIN, "-V"])
    info["ws_version"] = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()[0] \
        if (r.stdout or r.stderr) else "?"
    info["rs"] = discover_rs()
    info["root_id_run_mode"] = run(["setpriv", "--reuid=0", "--regid=0", "--init-groups", "--",
                                    "id"]).stdout.strip()
    info["alice_id"] = run(["id", "alice"]).stdout.strip()
    try:
        with open("/proc/self/status") as f:
            info["proc_status"] = [l.strip() for l in f
                                   if l.startswith(("NoNewPrivs", "CapEff", "Seccomp"))]
    except OSError:
        pass
    return info


def install_policy(text):
    tmp = SUDOERS + ".sdtmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o440)
    os.chown(tmp, 0, 0)
    os.replace(tmp, SUDOERS)


ENV = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root",
       "USER=root", "LOGNAME=root", "LANG=C.UTF-8", "TERM=dumb"]


def _err(r):
    return " | ".join(l.strip() for l in (r.stderr or "").splitlines() if l.strip())[:600]


def attempt_run(binary, rq):
    cmd = (["setpriv", "--reuid=0", "--regid=0", "--init-groups", "--", "/usr/bin/env", "-i"]
           + ENV + run_argv(binary, rq))
    r = run(cmd, timeout=25, cwd="/")
    probe = parse_probe(r.stdout)
    return {"decision": ALLOW if probe else DENY, "probe": probe, "rc": r.returncode,
            "err": _err(r)}


def attempt_list(binary, rq):
    r = run(["/usr/bin/env", "-i"] + ENV + list_argv(binary, rq), timeout=25, cwd="/")
    return {"decision": list_decision(r.returncode, r.stdout), "probe": None,
            "rc": r.returncode, "out": (r.stdout or "").strip()[:300], "err": _err(r)}


def repeat(fn, binary, rq, n):
    xs = [fn(binary, rq) for _ in range(max(1, n))]
    first = dict(xs[0])
    first["stable"] = len({x["decision"] for x in xs}) == 1
    return first


def preflight(impls, host):
    """Per implementation and mode: does the observation method work at all?"""
    out = {"run": {}, "list": {}, "list_rootline": False}
    run_checks = (
        (["root ALL=(ALL:ALL) NOPASSWD: ALL"], {}, ALLOW, {"uid": 0}),
        (["bob ALL=(ALL:ALL) NOPASSWD: ALL"], {}, DENY, None),
        (["root ALL=(ALL:ALL) NOPASSWD: ALL"], {"runas_user": "alice"}, ALLOW,
         {"uid": ALICE_UID}),
        (["root ALL=(ALL:ALL) NOPASSWD: ALL"], {"runas_group": "svcgrp"}, ALLOW,
         {"uid": 0, "egid": SVCGRP_GID}),
    )
    for k, b in impls:
        got = []
        for lines, rq, exp, probe_exp in run_checks:
            install_policy(render(lines, host, None))
            a = attempt_run(b, dict({"invoker": "root"}, **rq))
            ok = a["decision"] == exp and all((a["probe"] or {}).get(pk) == pv
                                              for pk, pv in (probe_exp or {}).items())
            got.append({"lines": lines, "request": rq, "expect": exp, "got": a, "ok": ok})
        out["run"][k] = {"ok": all(g["ok"] for g in got), "checks": got}
    for rootline in (False, True):
        res = {}
        for k, b in impls:
            got = []
            for lines, exp in ((["alice ALL=(ALL:ALL) NOPASSWD: ALL"], ALLOW),
                               (["bob ALL=(ALL:ALL) NOPASSWD: ALL"], DENY)):
                install_policy(render(lines, host, None, rootline))
                a = attempt_list(b, {"invoker": "alice"})
                got.append({"lines": lines, "expect": exp, "got": a, "ok": a["decision"] == exp})
            res[k] = {"ok": all(g["ok"] for g in got), "checks": got}
        out["list"] = res
        out["list_rootline"] = rootline
        if all(v["ok"] for v in res.values()):
            break
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="/out")
    ap.add_argument("--repeats", type=int, default=2)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("must run as root inside a disposable container")
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    info = setup()
    host = info["hostname"]
    rs_versions = sorted(v for v, d in info["rs"].items() if d.get("sudo"))
    impls = [("ws", WS_BIN)] + [("rs-" + v, info["rs"][v]["sudo"]) for v in rs_versions]
    pre = preflight(impls, host)
    info["preflight"] = pre
    write_json(os.path.join(a.out, "env.json"), info)
    run_ok = {k for k, v in pre["run"].items() if v["ok"]}
    list_ok = {k for k, v in pre["list"].items() if v["ok"]}
    if "ws" not in run_ok and "ws" not in list_ok:
        write_json(os.path.join(a.out, "summary.json"), {"status": "preflight_failed",
                                                         "preflight": pre})
        print(json.dumps(pre, indent=1, default=str)[:20000])
        return 2
    info["fqdn_host"] = None  # F cases need sethostname (CAP_SYS_ADMIN): not available
    records = []
    for c in unify_cases():
        rec = dict(c)
        rec["modes"] = {}
        hostcase = info["hostcase"]
        na = None
        if c["needs"] == "case" and not hostcase:
            na = "host name has no usable letter-case variant"
        if c["needs"] == "fqdn":
            na = "the container may not set its host name (no CAP_SYS_ADMIN)"
        # run mode
        lines, rq = run_mode_plan(c)
        if na or lines is None:
            rec["modes"]["run"] = {"na": na or rq}
        else:
            pol = render(lines, host, hostcase)
            install_policy(pol)
            impl = {}
            for k, b in impls:
                impl[k] = repeat(attempt_run, b, rq, a.repeats) if k in run_ok else \
                    {"decision": NA, "probe": None, "err": "preflight failed", "stable": True}
            rec["modes"]["run"] = {"policy": pol, "request": rq, "impl": impl}
        # list mode (study 3 only)
        if c["study"] == "hosts":
            if na:
                rec["modes"]["list"] = {"na": na}
            else:
                pol = render(c["lines"], host, hostcase, pre["list_rootline"])
                install_policy(pol)
                impl = {}
                for k, b in impls:
                    impl[k] = repeat(attempt_list, b, c["request"], a.repeats) if k in list_ok \
                        else {"decision": NA, "probe": None, "err": "preflight failed",
                              "stable": True}
                rec["modes"]["list"] = {"policy": pol, "request": c["request"], "impl": impl}
        records.append(rec)
        line = "%-5s %-4s" % (c["study"][:5], c["id"])
        for mode in ("run", "list"):
            m = rec["modes"].get(mode)
            if m and not m.get("na"):
                line += "  %s: %s" % (mode, " ".join("%s=%s" % (k, v["decision"])
                                                     for k, v in m["impl"].items()))
            elif m:
                line += "  %s: n/a" % mode
        print(line, flush=True)
    grades = summarize(records, rs_versions)
    agree = agreement(records, rs_versions)
    write_json(os.path.join(a.out, "env.json"), info)
    write_json(os.path.join(a.out, "results.json"), records)
    write_json(os.path.join(a.out, "summary.json"),
               {"status": "ok", "runner": VERSION, "cases": len(records),
                "rs_versions": rs_versions, "run_mode_ok": sorted(run_ok),
                "list_mode_ok": sorted(list_ok), "list_rootline": pre["list_rootline"],
                "grades": grades, "run_vs_list": agree, "minutes": (time.time() - t0) / 60.0})
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(render_md(info, records, grades, agree, rs_versions))
    print(json.dumps({"grades": grades, "run_vs_list": agree}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
