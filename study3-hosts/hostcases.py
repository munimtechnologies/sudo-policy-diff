#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""sudo-policy-diff, study 3: host and alias matching cases.

Fixed, hand-written cases testing predictions made by reading the source of
both implementations (see PREREG-hosts.md):

  H  A Host_Alias / User_Alias whose definition uses syntax Todd Miller's sudo
     supports but sudo-rs's parser rejects (IPv4 address or network, IPv6
     network, host wildcard, +netgroup). sudo-rs reports the line, drops it,
     keeps running, and a NEGATED reference to the now-undefined alias
     ("ALL, !PROD") is silently skipped. Predicted: sudo DENY, sudo-rs ALLOW.
  S  Host names that differ only in letter case. sudo compares host names
     with strcasecmp; sudo-rs with exact byte equality. Negated -> sudo DENY,
     sudo-rs ALLOW, with no diagnostic at all.
  F  Machine host name is fully qualified, sudoers uses the short name. sudo
     compares a dot-less pattern with the short host; sudo-rs compares with
     the full gethostname() string. Negated -> sudo DENY, sudo-rs ALLOW.
     Only run if the container may set its host name.
  R  Restrictive mirrors (sudo ALLOW, sudo-rs DENY).
  C  Controls: both must agree.
  K  Exploratory: a Cmnd_Alias with a sudo regular expression.

Runs INSIDE a disposable container as root, never on a real machine: it
creates test users, rewrites /etc/sudoers and may change the host name.
"""

import argparse
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time

WS = "/usr/bin/sudo.ws"
RS = "/usr/bin/sudo-rs"
IMPLS = (("ws", WS), ("rs", RS))
VISUDO = (("ws", "/usr/sbin/visudo.ws"), ("rs", "/usr/bin/visudo-rs"))
SUDOERS = "/etc/sudoers"
TS_DIRS = ("/run/sudo/ts", "/var/run/sudo/ts", "/run/sudo-rs/ts",
           "/var/run/sudo-rs/ts", "/var/lib/sudo/ts")
PROBE = "/usr/local/bin/probe"
PROBE_PREFIX = "SUDODIFF-PROBE "
HEADER = ("# sudo-policy-diff study 3 policy", "Defaults timestamp_timeout=0")
ALLOW, DENY, NA = "ALLOW", "DENY", "N/A"
FQDN_SUFFIX = ".sudodiff.test"

GROUPS = (("team", 3001),)
USERS = (("alice", 2001, ("team",)), ("bob", 2002, ("team",)), ("carol", 2003, ()))

GRANT = "(root) NOPASSWD: " + PROBE


def _case(cid, family, kind, lines, ws, rs, why, invoker="alice", needs=None):
    return {"id": cid, "family": family, "kind": kind, "lines": list(lines),
            "invoker": invoker, "expect_ws": ws, "expect_rs": rs, "why": why,
            "needs": needs}


def _neg_alias(defn):
    return ["Host_Alias PROD = " + defn, "alice ALL, !PROD = " + GRANT]


CASES = (
    # ---- H: alias dropped by sudo-rs's parser -> negated reference skipped
    _case("H1", "H", "divergence", _neg_alias("{HOST}, 10.99.0.0/16"), DENY, ALLOW,
          "IPv4 network in a Host_Alias"),
    _case("H2", "H", "divergence", _neg_alias("{HOST}, 192.0.2.10"), DENY, ALLOW,
          "IPv4 address in a Host_Alias"),
    _case("H3", "H", "divergence", _neg_alias("{HOST}, 2001:db8::/32"), DENY, ALLOW,
          "IPv6 network in a Host_Alias"),
    _case("H4", "H", "divergence", _neg_alias("{HOST}, db-*"), DENY, ALLOW,
          "host wildcard in a Host_Alias"),
    _case("H5", "H", "divergence", _neg_alias("{HOST}, +prodhosts"), DENY, ALLOW,
          "netgroup in a Host_Alias"),
    _case("H6", "H", "divergence",
          ["User_Alias BLOCKED = alice, +contractors", "ALL, !BLOCKED ALL = " + GRANT],
          DENY, ALLOW, "netgroup in a User_Alias, negated in the user list"),
    # ---- S: letter case of the host name (silent)
    _case("S1", "S", "divergence", ["alice ALL, !{HOSTCASE} = " + GRANT], DENY, ALLOW,
          "negated host name in other letter case", needs="case"),
    _case("S2", "S", "divergence", _neg_alias("{HOSTCASE}"), DENY, ALLOW,
          "negated Host_Alias naming the host in other letter case", needs="case"),
    # ---- R: restrictive mirrors
    _case("R1", "R", "divergence", ["alice ALL, !10.99.0.0/16 = " + GRANT], ALLOW, DENY,
          "IPv4 network directly in the rule: sudo-rs drops the whole grant"),
    _case("R2", "R", "divergence",
          ["Host_Alias OK = {HOST}, 10.99.0.0/16", "alice OK = " + GRANT], ALLOW, DENY,
          "positive Host_Alias dropped by sudo-rs"),
    _case("R3", "R", "divergence", ["alice {HOSTCASE} = " + GRANT], ALLOW, DENY,
          "positive host name in other letter case", needs="case"),
    # ---- C: controls
    _case("C1", "C", "control", ["alice ALL, !{HOST} = " + GRANT], DENY, DENY,
          "negated exact host name"),
    _case("C2", "C", "control", _neg_alias("{HOST}"), DENY, DENY, "negated alias, exact name"),
    _case("C3", "C", "control", _neg_alias("otherhost"), ALLOW, ALLOW,
          "negated alias naming another host"),
    _case("C4", "C", "control", ["alice {HOST} = " + GRANT], ALLOW, ALLOW, "exact host name"),
    _case("C5", "C", "control", _neg_alias("{HOST}, otherhost"), DENY, DENY,
          "negated alias, two plain names"),
    _case("C6", "C", "control",
          ["User_Alias BLOCKED = alice, carol", "ALL, !BLOCKED ALL = " + GRANT],
          DENY, DENY, "negated User_Alias, plain names"),
    _case("C7", "C", "control",
          ["User_Alias BLOCKED = alice, carol", "ALL, !BLOCKED ALL = " + GRANT],
          ALLOW, ALLOW, "negated User_Alias, user not in it", invoker="bob"),
    # ---- K: exploratory
    _case("K1", "K", "divergence",
          ["Cmnd_Alias BLOCKED = /usr/bin/true, ^/usr/local/bin/pro.e$",
           "alice ALL = (root) NOPASSWD: /usr/local/bin/*, !BLOCKED"], DENY, ALLOW,
          "sudo regular expression in a negated Cmnd_Alias (exploratory)"),
    # ---- F: fully qualified machine host name (run last; may be N/A)
    _case("F1", "F", "divergence", ["alice ALL, !{SHORT} = " + GRANT], DENY, ALLOW,
          "negated short name, machine name is fully qualified", needs="fqdn"),
    _case("F2", "F", "divergence", _neg_alias("{SHORT}"), DENY, ALLOW,
          "negated alias of short name, machine name is fully qualified", needs="fqdn"),
    _case("F3", "F", "control", ["alice ALL, !{HOST} = " + GRANT], DENY, DENY,
          "negated full name, machine name is fully qualified", needs="fqdn"),
    _case("F4", "F", "divergence", ["alice {SHORT} = " + GRANT], ALLOW, DENY,
          "positive short name, machine name is fully qualified", needs="fqdn"),
)

ALIAS_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def flip_case(host):
    """Host name with its LAST letter's case flipped, or None if impossible.

    The first character is never changed, so the result can never start with
    an upper-case letter and be read as an alias name by either parser."""
    for i in range(len(host) - 1, 0, -1):
        ch = host[i]
        if ch.isascii() and ch.isalpha():
            out = host[:i] + ch.swapcase() + host[i + 1:]
            if out == host or ALIAS_RE.match(out) or host[0].isupper():
                return None
            return out
    return None


def short_of(host):
    return host.split(".", 1)[0]


def render(lines, host, hostcase=None):
    text = "\n".join(list(HEADER) + list(lines)) + "\n"
    text = text.replace("{HOSTCASE}", hostcase or "NO_CASE_VARIANT")
    text = text.replace("{SHORT}", short_of(host))
    return text.replace("{HOST}", host)


def argv_for(binary):
    return [binary, "-n", PROBE]


def parse_probe(stdout):
    for line in (stdout or "").splitlines():
        if line.startswith(PROBE_PREFIX):
            try:
                rec = json.loads(line[len(PROBE_PREFIX):])
            except ValueError:
                return None
            return rec if isinstance(rec, dict) else None
    return None


def cls(decision):
    return ALLOW if str(decision).startswith("ALLOW") else (NA if decision == NA else DENY)


def judge(case, ws_dec, rs_dec):
    w, r = cls(ws_dec), cls(rs_dec)
    if NA in (w, r):
        return "n/a"
    if (w, r) == (case["expect_ws"], case["expect_rs"]):
        return "as_predicted"
    if w == r:
        return "unexpected_agree" if case["kind"] == "divergence" else "unexpected_both_" + w
    return "unexpected_divergence"


def grade(results):
    """Pre-registered hypotheses (PREREG-hosts.md section 4)."""
    by = {x["id"]: x for x in results}

    def ok(ids):
        xs = [by[i] for i in ids if i in by]
        if not xs or any(x["verdict"] == "n/a" for x in xs):
            return "n/a"
        return all(x["verdict"] == "as_predicted" and x["stable"] for x in xs)

    def count(fam):
        xs = [x for x in results if x["family"] == fam and x["kind"] == "divergence"]
        return "%d/%d" % (sum(x["verdict"] == "as_predicted" and x["stable"] for x in xs),
                          len(xs))

    controls = [x for x in results if x["kind"] == "control" and x["verdict"] != "n/a"]
    perm = [x for x in results if x["kind"] == "divergence" and x["expect_rs"] == ALLOW
            and x["verdict"] == "as_predicted"]
    return {
        "H1_dropped_alias_fail_open": ok(("H1", "H6")),
        "H1_count": count("H"),
        "H2_case_silent_fail_open": ok(("S1", "S2")),
        "H3_fqdn_silent_fail_open": ok(("F1", "F2")),
        "H4_restrictive_mirrors": ok(("R1", "R2")),
        "H4_count": count("R"),
        "H5_controls_agree": bool(controls) and all(
            cls(x["ws"]["decision"]) == cls(x["rs"]["decision"]) for x in controls),
        "H6_gain_is_root": bool(perm) and all(
            (x["rs"]["probe"] or {}).get("uid") == 0 for x in perm),
        "K1_exploratory": by["K1"]["verdict"] if "K1" in by else "n/a",
    }


def render_md(env, results, grades):
    lines = ["# sudo-policy-diff study 3: host and alias matching", "",
             "packages: %s" % (env.get("dpkg", "").strip().replace("\n", "; ")),
             "host name: `%s`; case variant: `%s`; fqdn set: %s" % (
                 env.get("hostname"), env.get("hostcase"), env.get("fqdn_host")), "",
             "| id | kind | policy | invoker | sudo | sudo-rs | predicted | verdict | stable"
             " | rs stderr |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for x in results:
        lines.append("| %s | %s | `%s` | %s | %s | %s | %s/%s | %s | %s | %s |" % (
            x["id"], x["kind"], " ; ".join(x["lines"]), x["invoker"], x["ws"]["decision"],
            x["rs"]["decision"], x["expect_ws"], x["expect_rs"], x["verdict"], x["stable"],
            (x["rs"].get("err") or "").replace("|", "/")[:160]))
    lines += ["", "## Hypotheses (raw)", ""]
    for k, v in grades.items():
        lines.append("- %s: %s" % (k, v))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------ container I/O

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


def write_file(path, text, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)
    os.chown(path, 0, 0)


def probe_script():
    return (
        "#!/usr/bin/python3 -I\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "import json, os, sys\n"
        "rec = {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),\n"
        "       'egid': os.getegid(), 'argv': sys.argv[1:]}\n"
        "sys.stdout.write(%r + json.dumps(rec, sort_keys=True) + '\\n')\n"
    ) % PROBE_PREFIX


def add_hosts_entry(name):
    try:
        with open("/etc/hosts") as f:
            names = f.read().split()
        if name not in names:
            with open("/etc/hosts", "a") as f:
                f.write("127.0.1.1\t%s %s\n" % (name, short_of(name)))
        return None
    except OSError as e:
        return repr(e)


def pam_nodelay():
    p = "/etc/pam.d/common-auth"
    try:
        with open(p) as f:
            txt = f.read()
    except OSError:
        return "missing"
    out = []
    for ln in txt.splitlines():
        if "pam_unix.so" in ln and not ln.lstrip().startswith("#") and "nodelay" not in ln:
            ln += " nodelay"
        out.append(ln)
    with open(p, "w") as f:
        f.write("\n".join(out) + "\n")
    return "ok"


def setup():
    info = {}
    for name, gid in GROUPS:
        if run(["getent", "group", name]).returncode != 0:
            must(run(["groupadd", "-g", str(gid), name]), "groupadd " + name)
    for name, uid, groups in USERS:
        if run(["getent", "passwd", name]).returncode == 0:
            continue
        cmd = ["useradd", "-m", "-U", "-u", str(uid), "-s", "/bin/sh"]
        if groups:
            cmd += ["-G", ",".join(groups)]
        must(run(cmd + [name]), "useradd " + name)
    pw = {u: "sd-" + secrets.token_hex(10) for u in ["root"] + [x[0] for x in USERS]}
    must(run(["chpasswd"], input="".join("%s:%s\n" % kv for kv in pw.items())), "chpasswd")
    write_file(PROBE, probe_script(), 0o755)
    info["pam_nodelay"] = pam_nodelay()
    if not os.path.exists("/etc/pam.d/sudo"):
        write_file("/etc/pam.d/sudo", "@include common-auth\n@include common-account\n"
                   "@include common-session-noninteractive\n", 0o644)
        info["pam_sudo_written"] = True
    if os.path.lexists("/etc/sudoers-rs"):
        os.unlink("/etc/sudoers-rs")
        info["removed_sudoers_rs"] = True
    host = socket.gethostname()
    info["hostname"] = host
    info["hosts_error"] = add_hosts_entry(host)
    info["hostcase"] = flip_case(host)
    r = run(["dpkg-query", "-W", "-f", "${Package} ${Version}\n", "sudo", "sudo-rs",
             "util-linux", "libc6"])
    info["dpkg"] = r.stdout
    for k, b in IMPLS:
        r = run([b, "-V"])
        info[k + "_V"] = ((r.stdout or "") + (r.stderr or ""))[:4000]
    r = run(["hostname", "-I"])
    info["addresses"] = (r.stdout or r.stderr or "").strip()
    try:
        with open("/etc/nsswitch.conf") as f:
            info["nsswitch_netgroup"] = [l.strip() for l in f if l.startswith("netgroup")]
    except OSError:
        pass
    try:
        with open("/proc/self/status") as f:
            info["proc_status"] = [l.strip() for l in f
                                   if l.startswith(("NoNewPrivs", "CapEff", "CapBnd", "Seccomp"))]
    except OSError:
        pass
    return info, pw


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
        out[k] = {"rc": r.returncode, "err": ((r.stderr or "") + (r.stdout or ""))[-400:]}
    return out


def attempt(binary, invoker):
    env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME=/home/" + invoker, "USER=" + invoker, "LOGNAME=" + invoker,
           "LANG=C.UTF-8", "TERM=dumb"]
    cmd = (["setpriv", "--reuid=" + invoker, "--regid=" + invoker, "--init-groups", "--",
            "/usr/bin/env", "-i"] + env + argv_for(binary))
    r = run(cmd, timeout=20, cwd="/", errors="replace")
    probe = parse_probe(r.stdout)
    err = " | ".join(l.strip() for l in (r.stderr or "").splitlines() if l.strip())[:600]
    return {"decision": "ALLOW_NOPASSWD" if probe else "DENY", "probe": probe,
            "rc": r.returncode, "err": err}


def preflight(host):
    checks = []
    for name, lines, expect in (("nopasswd_all", ["alice ALL=(ALL:ALL) NOPASSWD: ALL"], ALLOW),
                                ("no_rule", ["bob ALL=(ALL:ALL) NOPASSWD: ALL"], DENY)):
        install_policy(render(lines, host))
        got = {k: attempt(b, "alice") for k, b in IMPLS}
        checks.append({"name": name, "expect": expect, "got": got,
                       "ok": all(cls(g["decision"]) == expect for g in got.values())})
    root_ok = all((g["probe"] or {}).get("uid") == 0 for g in checks[0]["got"].values())
    return {"ok": bool(all(c["ok"] for c in checks) and root_ok), "checks": checks}


def try_fqdn(host):
    """Make the machine host name fully qualified. Returns the new name or None."""
    if "." in host:
        return host
    new = host + FQDN_SUFFIX
    try:
        socket.sethostname(new)
    except (OSError, AttributeError):
        return None
    if socket.gethostname() != new:
        return None
    add_hosts_entry(new)
    return new


def run_case(c, host, hostcase, repeats):
    if c["needs"] == "case" and not hostcase:
        return None
    install_policy(render(c["lines"], host, hostcase))
    vis = visudo_check()
    runs = [{k: attempt(b, c["invoker"]) for k, b in IMPLS} for _ in range(max(1, repeats))]
    sig = [(r["ws"]["decision"], r["rs"]["decision"]) for r in runs]
    x = dict(c)
    x.update({"policy": render(c["lines"], host, hostcase), "ws": runs[0]["ws"],
              "rs": runs[0]["rs"], "visudo": vis, "stable": len(set(sig)) == 1,
              "verdict": judge(c, runs[0]["ws"]["decision"], runs[0]["rs"]["decision"])})
    return x


def na_result(c, why):
    x = dict(c)
    x.update({"ws": {"decision": NA, "probe": None, "err": why},
              "rs": {"decision": NA, "probe": None, "err": why},
              "visudo": {}, "stable": True, "verdict": "n/a"})
    return x


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="/out")
    ap.add_argument("--repeats", type=int, default=2)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("must run as root inside a disposable container")
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    info, _pw = setup()
    host = info["hostname"]
    pre = preflight(host)
    info["preflight"] = pre
    write_json(os.path.join(a.out, "env.json"), info)
    if not pre["ok"]:
        write_json(os.path.join(a.out, "summary.json"),
                   {"status": "preflight_failed", "preflight": pre})
        print(json.dumps(pre, indent=1, default=str))
        return 2
    results = []
    for c in CASES:
        if c["needs"] == "fqdn":
            continue
        x = run_case(c, host, info["hostcase"], a.repeats)
        if x is None:
            x = na_result(c, "host name has no usable letter-case variant")
        results.append(x)
        print("%-3s %-10s ws=%-15s rs=%-15s %s" % (x["id"], x["kind"], x["ws"]["decision"],
                                                    x["rs"]["decision"], x["verdict"]))
    fq = try_fqdn(host)
    info["fqdn_host"] = fq
    for c in CASES:
        if c["needs"] != "fqdn":
            continue
        x = run_case(c, fq, None, a.repeats) if fq else na_result(
            c, "container may not set its host name")
        results.append(x)
        print("%-3s %-10s ws=%-15s rs=%-15s %s" % (x["id"], x["kind"], x["ws"]["decision"],
                                                    x["rs"]["decision"], x["verdict"]))
    if fq and fq != host:
        try:
            socket.sethostname(host)
        except OSError:
            pass
    grades = grade(results)
    write_json(os.path.join(a.out, "env.json"), info)
    write_json(os.path.join(a.out, "results.json"), results)
    write_json(os.path.join(a.out, "summary.json"),
               {"status": "ok", "cases": len(results), "grades": grades,
                "minutes": (time.time() - t0) / 60.0})
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(render_md(info, results, grades))
    print(json.dumps(grades, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
