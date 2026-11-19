#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""sudo-policy-diff runner.

Runs INSIDE a disposable Ubuntu 26.10 container as root, never on a real
machine: it creates test users with random throwaway passwords (kept only in
memory), rewrites /etc/sudoers, and runs every generated request through Todd
Miller's sudo (/usr/bin/sudo.ws) and sudo-rs (/usr/bin/sudo-rs) as the
invoking user. See PREREG.md for the frozen method and predictions.
"""

import argparse
import json
import os
import random
import secrets
import socket
import subprocess
import sys
import time

import outcome as O
import sudoers_gen as G

WS = "/usr/bin/sudo.ws"
RS = "/usr/bin/sudo-rs"
IMPLS = (("ws", WS), ("rs", RS))
VISUDO = (("ws", "/usr/sbin/visudo.ws"), ("rs", "/usr/bin/visudo-rs"))
SUDOERS = "/etc/sudoers"
TS_DIRS = ("/run/sudo/ts", "/var/run/sudo/ts", "/run/sudo-rs/ts",
           "/var/run/sudo-rs/ts", "/var/lib/sudo/ts")


def run(cmd, timeout=60, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
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


def write_file(path, text, mode, uid=0, gid=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


# ------------------------------------------------------------------ setup

def setup():
    info = {}
    for name, gid in G.GROUPS:
        if run(["getent", "group", name]).returncode != 0:
            must(run(["groupadd", "-g", str(gid), name]), "groupadd " + name)
    for name, uid, gid, groups in G.USERS:
        if run(["getent", "passwd", name]).returncode == 0:
            continue
        if run(["getent", "group", str(gid)]).returncode != 0:
            must(run(["groupadd", "-g", str(gid), name]), "groupadd " + name)
        cmd = ["useradd", "-m", "-u", str(uid), "-g", str(gid), "-s", "/bin/sh"]
        if groups:
            cmd += ["-G", ",".join(groups)]
        must(run(cmd + [name]), "useradd " + name)
    pw = {u: "sd-" + secrets.token_hex(10) for u in ["root"] + [x[0] for x in G.USERS]}
    must(run(["chpasswd"], input="".join("%s:%s\n" % kv for kv in pw.items())), "chpasswd")

    for path, tag in G.PROBES:
        write_file(path, G.probe_script(tag), 0o755)
    for user in G.INVOKERS:
        uid, gid = [(u[1], u[2]) for u in G.USERS if u[0] == user][0]
        home = "/home/" + user
        os.chmod(home, 0o755)
        for kind, path, x in G.user_files(user):
            d = os.path.dirname(path)
            os.makedirs(d, exist_ok=True)
            os.chown(d, uid, gid)
            os.chmod(d, 0o755)
            if os.path.lexists(path):
                os.unlink(path)
            if kind == "symlink":
                os.symlink(x, path)
                os.lchown(path, uid, gid)
            else:
                write_file(path, G.probe_script(x), 0o755, uid, gid)

    info["pam_nodelay"] = pam_nodelay()
    if not os.path.exists("/etc/pam.d/sudo"):
        write_file("/etc/pam.d/sudo", "@include common-auth\n@include common-account\n"
                   "@include common-session-noninteractive\n", 0o644)
        info["pam_sudo_written"] = True
    for p in ("/etc/sudoers-rs",):
        if os.path.lexists(p):
            os.unlink(p)
            info["removed_" + p] = True
    host = socket.gethostname()
    try:
        with open("/etc/hosts") as f:
            hosts = f.read()
        if host not in hosts.split():
            with open("/etc/hosts", "a") as f:
                f.write("127.0.1.1\t%s\n" % host)
    except OSError as e:
        info["hosts_error"] = repr(e)
    info["hostname"] = host
    info.update(versions())
    return info, pw


def pam_nodelay():
    p = "/etc/pam.d/common-auth"
    try:
        with open(p) as f:
            txt = f.read()
    except OSError:
        return "missing"
    out, changed = [], False
    for ln in txt.splitlines():
        if "pam_unix.so" in ln and not ln.lstrip().startswith("#") and "nodelay" not in ln:
            ln += " nodelay"
            changed = True
        out.append(ln)
    with open(p, "w") as f:
        f.write("\n".join(out) + "\n")
    return "changed" if changed else "unchanged"


def versions():
    info = {}
    r = run(["dpkg-query", "-W", "-f", "${Package} ${Version}\n", "sudo", "sudo-rs",
             "util-linux", "python3", "libpam-modules"])
    info["dpkg"] = r.stdout
    for k, b in IMPLS:
        r = run([b, "-V"])
        info[k + "_V"] = ((r.stdout or "") + (r.stderr or ""))[:8000]
        try:
            st = os.stat(b)
            info[k + "_mode"] = "%o uid=%d" % (st.st_mode, st.st_uid)
        except OSError as e:
            info[k + "_mode"] = repr(e)
    try:
        with open("/proc/self/status") as f:
            info["no_new_privs"] = [l.strip() for l in f if l.startswith("NoNewPrivs")]
    except OSError:
        pass
    try:
        with open("/etc/os-release") as f:
            info["os_release"] = f.read()
    except OSError:
        pass
    return info


# --------------------------------------------------------------- running

def install_policy(text):
    tmp = SUDOERS + ".sdtmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o440)
    os.chown(tmp, 0, 0)
    os.replace(tmp, SUDOERS)
    for d in TS_DIRS:
        if os.path.isdir(d):
            for n in os.listdir(d):
                try:
                    os.unlink(os.path.join(d, n))
                except OSError:
                    pass


def visudo_check():
    out = {}
    for k, b in VISUDO:
        r = run([b, "-c", "-f", SUDOERS], timeout=20)
        out[k] = {"rc": r.returncode, "err": ((r.stderr or "") + (r.stdout or ""))[-300:]}
    return out


def attempt(binary, req, stage, password):
    inv = req["invoker"]
    argv = G.sudo_argv(binary, req, "-n" if password is None else "-S")
    env = G.invoker_env(req)
    cmd = (["setpriv", "--reuid=" + inv, "--regid=" + inv, "--init-groups", "--",
            "/usr/bin/env", "-i"] + ["%s=%s" % kv for kv in sorted(env.items())] + argv)
    try:
        r = subprocess.run(cmd, input=(password + "\n") if password else "",
                           capture_output=True, text=True, timeout=20,
                           cwd=G.expand(req["cwd"], inv), errors="replace")
        rc, so, se = r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        rc, so, se = 124, "", "TIMEOUT"
    return {"stage": stage, "rc": rc, "probe": O.parse_probe(so), "err": O.short_err(se)}


def stages(req, pw):
    inv = req["invoker"]
    tgt = G.target_user(req)
    out = [("nopass", None), ("pw_invoker", pw[inv]), ("pw_root", pw["root"])]
    if tgt and tgt not in (inv, "root") and tgt in pw:
        out.append(("pw_target", pw[tgt]))
    return out


def eval_impl(binary, req, pw):
    attempts = []
    for stage, p in stages(req, pw):
        a = attempt(binary, req, stage, p)
        attempts.append(a)
        if a["probe"] is not None:
            break
    dec, probe = O.decide(attempts)
    return {"decision": dec, "probe": probe,
            "attempts": [{k: a[k] for k in ("stage", "rc", "err")} for a in attempts]}


def eval_both(req, pw):
    res = {k: eval_impl(b, req, pw) for k, b in IMPLS}
    f = O.compare(res["ws"]["decision"], res["ws"]["probe"],
                  res["rs"]["decision"], res["rs"]["probe"], G.user_env(req))
    return res, f


def slim(res, req):
    ue = G.user_env(req)
    out = {}
    for k, r in res.items():
        p = r["probe"]
        core = None
        if p is not None:
            env = p.get("env") or {}
            core = {x: p.get(x) for x in ("tag", "exe", "argv", "uid", "euid", "gid",
                                         "egid", "groups", "cwd", "umask")}
            core["env_user"] = {n: env.get(n) for n in sorted(ue) if n in env}
            core["env_ld"] = {n: v for n, v in sorted(env.items()) if n.startswith("LD_")}
            core["env_names"] = sorted(env)
        out[k] = {"decision": r["decision"], "probe": core, "attempts": r["attempts"]}
    return out


def reproduces(lines, req, k, pw, host):
    install_policy(G.render_policy(lines, host))
    res, f = eval_both(req, pw)
    return any(O.key(x) == k for x in f), res, f


def minimize(lines, req, k, pw, host, deadline):
    lines = list(lines)
    req = json.loads(json.dumps(req))
    changed, passes = True, 0
    while changed and passes < 4 and time.time() < deadline:
        changed, passes = False, passes + 1
        i = 0
        while i < len(lines) and time.time() < deadline:
            trial = lines[:i] + lines[i + 1:]
            if reproduces(trial, req, k, pw, host)[0]:
                lines, changed = trial, True
            else:
                i += 1
        for field, empty in (("cmdline_env", []), ("preserve_env", False), ("chdir", None),
                             ("runas_group", None), ("runas_user", None), ("args", [])):
            if req.get(field) != empty:
                t = dict(req)
                t[field] = empty
                if reproduces(lines, t, k, pw, host)[0]:
                    req, changed = t, True
        for name in list(req.get("env", {})):
            t = dict(req)
            t["env"] = {a: b for a, b in req["env"].items() if a != name}
            if reproduces(lines, t, k, pw, host)[0]:
                req, changed = t, True
    confirms = [reproduces(lines, req, k, pw, host)[0] for _ in range(2)]
    ok, res, f = reproduces(lines, req, k, pw, host)
    vis = visudo_check()
    return {"key": list(k), "policy_lines": lines, "policy": G.policy_template(lines),
            "request": req, "argv_rs": G.sudo_argv(RS, req, "-n"),
            "stable": bool(ok and all(confirms)), "result": slim(res, req),
            "findings": f, "visudo": vis}


def preflight(pw, host):
    checks = []
    base = {"invoker": "alice", "runas_user": None, "runas_group": None,
            "cmd": "/usr/local/bin/probe", "args": [], "cwd": "/", "env": {},
            "cmdline_env": [], "preserve_env": False, "chdir": None}
    for name, lines, expect in (
            ("nopasswd_all", ["alice ALL=(ALL:ALL) NOPASSWD: ALL"], "ALLOW_NOPASSWD"),
            ("passwd_all", ["alice ALL=(ALL:ALL) ALL"], "ALLOW_PW_INVOKER"),
            ("no_rule", ["bob ALL=(ALL:ALL) ALL"], "DENY")):
        install_policy(G.render_policy(lines, host))
        got = {}
        for k, b in IMPLS:
            r = eval_impl(b, base, pw)
            got[k] = {"decision": r["decision"], "uid": (r["probe"] or {}).get("uid"),
                      "attempts": r["attempts"]}
        checks.append({"name": name, "expect": expect, "got": got,
                       "ok": all(g["decision"] == expect for g in got.values())})
    root_ok = all(g["uid"] == 0 for g in checks[0]["got"].values())
    return {"ok": bool(all(c["ok"] for c in checks) and root_ok), "checks": checks}


# ------------------------------------------------------------------- main

def write_summary(out, s):
    s["predictions_raw"] = O.grade(s)
    write_json(os.path.join(out, "summary.json"), s)
    lines = ["# sudo-policy-diff run summary", "",
             "status: %s; policies: %s; requests: %s; minutes: %.1f" % (
                 s.get("status"), s.get("policies"), s.get("requests"), s.get("elapsed_min", 0)),
             "", "## Finding counts (kind/direction)", ""]
    for k, v in s.get("finding_counts", {}).items():
        lines.append("- %s: %d" % (k, v))
    lines += ["", "## Control (sudo vs sudo re-run)", "", json.dumps(s.get("control", {})),
              "", "## visudo (ws/rs)", "", json.dumps(s.get("visudo", {})),
              "", "## Raw prediction grades", ""]
    for k, v in s["predictions_raw"].items():
        lines.append("- %s: %s" % (k, v))
    lines += ["", "## Minimized security-relevant findings", ""]
    for m in s.get("minimized_list", []):
        lines.append("### %s (stable=%s)" % (" | ".join(m["key"]), m["stable"]))
        lines.append("```\n%s```" % m["policy"])
        lines.append("argv: `%s`  invoker: %s  env: %s" % (
            " ".join(m["argv_rs"]), m["request"]["invoker"], m["request"].get("env")))
        lines.append("ws: %s / rs: %s" % (m["result"]["ws"]["decision"],
                                          m["result"]["rs"]["decision"]))
        lines.append("")
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="/out")
    ap.add_argument("--seed", type=int, default=20261117)
    ap.add_argument("--budget-minutes", type=float, default=75)
    ap.add_argument("--requests-per-policy", type=int, default=12)
    ap.add_argument("--control-requests", type=int, default=300)
    ap.add_argument("--max-minimize", type=int, default=25)
    ap.add_argument("--max-policies", type=int, default=1000000)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("must run as root inside a disposable container")
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    deadline = t0 + a.budget_minutes * 60
    info, pw = setup()
    host = info["hostname"]
    pre = preflight(pw, host)
    info["preflight"] = pre
    write_json(os.path.join(a.out, "env.json"), info)
    s = {"status": "running", "seed": a.seed, "preflight_ok": pre["ok"], "policies": 0,
         "requests": 0, "finding_counts": {}, "control": {"requests": 0, "noisy": 0},
         "visudo": {}, "minimized_list": [], "first_seen": {}}
    if not pre["ok"]:
        s["status"] = "preflight_failed"
        write_summary(a.out, s)
        print(json.dumps(pre, indent=1, default=str))
        return 2

    rng = random.Random(a.seed)
    counts, ctrl, vis = {}, {"requests": 0, "noisy": 0, "examples": []}, {}
    done_keys, n_sec = set(), 0
    cases = open(os.path.join(a.out, "cases.jsonl"), "w")
    min_reserve = 0.25 * (deadline - t0)
    while time.time() < deadline and s["policies"] < a.max_policies:
        lines = G.generate_policy(rng)
        reqs = [G.generate_request(rng) for _ in range(a.requests_per_policy)]
        s["policies"] += 1
        install_policy(G.render_policy(lines, host))
        vc = visudo_check()
        vk = "%s/%s" % ("ws_ok" if vc["ws"]["rc"] == 0 else "ws_bad",
                        "rs_ok" if vc["rs"]["rc"] == 0 else "rs_bad")
        vis[vk] = vis.get(vk, 0) + 1
        pending = []
        for j, req in enumerate(reqs):
            res, f = eval_both(req, pw)
            s["requests"] += 1
            for x in f:
                kk = "%s/%s" % (x["kind"], x["direction"])
                counts[kk] = counts.get(kk, 0) + 1
            rec = {"policy": s["policies"], "req": j, "policy_lines": lines,
                   "request": req, "result": slim(res, req), "findings": f}
            if j == 0:
                rec["visudo"] = vc
            if ctrl["requests"] < a.control_requests:
                ws2 = eval_impl(WS, req, pw)
                cf = O.compare(res["ws"]["decision"], res["ws"]["probe"],
                               ws2["decision"], ws2["probe"], G.user_env(req))
                cf = [x for x in cf if x["kind"] != "ENV_BASELINE"]
                ctrl["requests"] += 1
                if cf:
                    ctrl["noisy"] += 1
                    if len(ctrl["examples"]) < 10:
                        ctrl["examples"].append({"request": req, "findings": cf})
                rec["control"] = cf
            cases.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
            sec = [x for x in f if O.is_security(x)]
            if sec:
                n_sec += 1
            for x in sec:
                dk = O.key(x) + (G.request_feature(req),)
                ks = " | ".join(dk)
                if ks not in s["first_seen"]:
                    s["first_seen"][ks] = {"policy": s["policies"], "req": j, "count": 0}
                s["first_seen"][ks]["count"] += 1
                if dk not in done_keys:
                    pending.append((0 if x["direction"] == "permissive" else 1, dk, req))
        pending.sort(key=lambda t: t[0])
        for prio, dk, req in pending:
            if len(s["minimized_list"]) >= a.max_minimize or time.time() > deadline - 60:
                break
            if dk in done_keys:
                continue
            if time.time() > deadline - min_reserve and prio == 1:
                continue  # near the end, minimize only permissive findings
            done_keys.add(dk)
            m = minimize(lines, req, dk[:3], pw, host, deadline)
            m["feature"] = dk[3]
            s["minimized_list"].append(m)
            write_json(os.path.join(a.out, "findings.json"), s["minimized_list"])
        s["finding_counts"] = dict(sorted(counts.items()))
        s["control"] = ctrl
        s["visudo"] = vis
        s["requests_with_security_finding"] = n_sec
        s["elapsed_min"] = (time.time() - t0) / 60.0
        if s["policies"] % 10 == 0:
            cases.flush()
            write_summary(a.out, s)
    cases.close()
    s["status"] = "ok"
    s["elapsed_min"] = (time.time() - t0) / 60.0
    write_json(os.path.join(a.out, "findings.json"), s["minimized_list"])
    write_summary(a.out, s)
    print("policies=%d requests=%d security_requests=%d minimized=%d" % (
        s["policies"], s["requests"], n_sec, len(s["minimized_list"])))
    print(json.dumps(s["finding_counts"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
