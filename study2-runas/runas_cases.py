#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""sudo-policy-diff, study 2: targeted Runas negation cases.

Fixed, hand-written cases that test three predictions made by reading the
source of both implementations (see PREREG-runas.md):

  A  sudo-rs skips the Runas USER list when you run as yourself with -g and
     you are not in that group, so a negated entry that names you (!alice,
     !%wheel, !#2001, a negating Runas_Alias) is ignored. Todd Miller's sudo
     walks the user list and a matching negated entry is a final DENY.
  B  sudo-rs skips the Runas GROUP list when the target user is already in
     the requested group, so "!team" in the group list is ignored. sudo
     treats a matching negated group as DENY.
  C  sudo-rs checks the user list when you run as yourself with -g of a group
     you ARE in; sudo instead allows it when the group is listed ("sudo -g
     group" rescue in runaslist_matches). Restrictive in sudo-rs.

Controls check that the surrounding behaviour agrees. Runs INSIDE a
disposable container as root; reuses the sudodiff.py harness.
"""

import argparse
import json
import os
import sys
import time

PROBE = "/usr/local/bin/probe"
ALLOW, DENY = "ALLOW", "DENY"


def _req(invoker="alice", u=None, g=None):
    return {"invoker": invoker, "runas_user": u, "runas_group": g, "cmd": PROBE,
            "args": [], "cwd": "/", "env": {}, "cmdline_env": [],
            "preserve_env": False, "chdir": None}


def _case(cid, family, kind, lines, req, ws, rs, why):
    return {"id": cid, "family": family, "kind": kind, "lines": list(lines),
            "request": req, "expect_ws": ws, "expect_rs": rs, "why": why}


def _rule(runas):
    return "alice ALL = %s NOPASSWD: %s" % (runas, PROBE)


# Users (sudoers_gen.USERS): alice in team+wheel; bob in team; svc primary svcgrp.
CASES = (
    # ---- A: self + -g (not a member) + user list negates self -> rs permissive
    _case("A1", "A", "divergence", [_rule("(ALL, !alice : svcgrp)")], _req(g="svcgrp"),
          DENY, ALLOW, "user list !alice ignored by sudo-rs for sudo -g"),
    _case("A2", "A", "divergence", [_rule("(ALL, !alice : svcgrp)")],
          _req(u="alice", g="svcgrp"), DENY, ALLOW, "same with explicit -u alice"),
    _case("A3", "A", "divergence", [_rule("(ALL, !%wheel : svcgrp)")], _req(g="svcgrp"),
          DENY, ALLOW, "!%wheel names alice through group membership"),
    _case("A4", "A", "divergence",
          ["Runas_Alias NOTME = ALL, !alice", _rule("(NOTME : svcgrp)")], _req(g="svcgrp"),
          DENY, ALLOW, "negation inside a Runas_Alias"),
    _case("A5", "A", "divergence", [_rule("(ALL, !#2001 : svcgrp)")], _req(g="svcgrp"),
          DENY, ALLOW, "negated #uid of the invoker"),
    _case("A6", "A", "divergence", [_rule("(!alice : svcgrp)")], _req(g="svcgrp"),
          DENY, ALLOW, "negation-only user list"),
    _case("A7", "A", "control", [_rule("(ALL, !alice : svcgrp)")], _req(u="bob", g="svcgrp"),
          ALLOW, ALLOW, "another target, listed group"),
    _case("A8", "A", "control", [_rule("(ALL, !alice : svcgrp)")], _req(g="ops"),
          DENY, DENY, "unlisted group"),
    _case("A9", "A", "control", [_rule("(ALL, !alice : svcgrp)")], _req(),
          ALLOW, ALLOW, "default target root"),
    _case("A10", "A", "control", [_rule("(bob : svcgrp)")], _req(g="svcgrp"),
          ALLOW, ALLOW, "sudo's own rescue: self + listed group without negation"),
    # ---- B: target already in group + group list negates it -> rs permissive
    _case("B1", "B", "divergence", [_rule("(bob : ALL, !team)")], _req(u="bob", g="team"),
          DENY, ALLOW, "group list !team ignored when bob is in team"),
    _case("B2", "B", "divergence", [_rule("(bob : !team)")], _req(u="bob", g="team"),
          DENY, ALLOW, "negation-only group list"),
    _case("B3", "B", "divergence", [_rule("(alice : ALL, !wheel)")], _req(g="wheel"),
          DENY, ALLOW, "self, group alice is in, negated"),
    _case("B4", "B", "control", [_rule("(bob : ALL, !team)")], _req(u="bob", g="ops"),
          ALLOW, ALLOW, "non-negated group bob is not in"),
    _case("B5", "B", "control", [_rule("(bob : ALL, !team)")], _req(u="bob"),
          ALLOW, ALLOW, "no -g"),
    _case("B6", "B", "control", [_rule("(bob : ALL, !svcgrp)")], _req(u="bob", g="svcgrp"),
          DENY, DENY, "negated group bob is not in"),
    # ---- C: self + -g (member) + group listed, self not in user list -> rs restrictive
    _case("C1", "C", "divergence", [_rule("(root : team)")], _req(g="team"),
          ALLOW, DENY, "sudo rescue allows; sudo-rs checks user list"),
    _case("C2", "C", "divergence", [_rule("(bob : team)")], _req(u="alice", g="team"),
          ALLOW, DENY, "same with explicit -u alice"),
    _case("C3", "C", "control", [_rule("(root : svcgrp)")], _req(g="svcgrp"),
          ALLOW, ALLOW, "group alice is not in"),
    _case("C4", "C", "control", [_rule("(bob)")], _req(g="team"),
          DENY, DENY, "no group list"),
    # ---- D/E: empty and missing Runas specs (controls)
    _case("D1", "D", "control", [_rule("()")], _req(g="team"), ALLOW, ALLOW, "() own group"),
    _case("D2", "D", "control", [_rule("()")], _req(g="svcgrp"), DENY, DENY, "() other group"),
    _case("D3", "D", "control", [_rule("(:svcgrp)")], _req(g="svcgrp"), ALLOW, ALLOW,
          "(:g) listed group"),
    _case("D4", "D", "control", [_rule("(:svcgrp)")], _req(u="bob", g="svcgrp"), DENY, DENY,
          "(:g) other user"),
    _case("E1", "E", "control", ["alice ALL = NOPASSWD: %s" % PROBE], _req(g="team"),
          DENY, DENY, "no Runas, -g only"),
    _case("E2", "E", "control", ["alice ALL = NOPASSWD: %s" % PROBE], _req(u="root", g="root"),
          ALLOW, ALLOW, "no Runas, root's own group"),
)


def cls(decision):
    return ALLOW if str(decision).startswith("ALLOW") else DENY


def judge(case, ws_dec, rs_dec):
    """as_predicted / unexpected_* for one case."""
    w, r = cls(ws_dec), cls(rs_dec)
    if (w, r) == (case["expect_ws"], case["expect_rs"]):
        return "as_predicted"
    if w == r:
        return "unexpected_agree" if case["kind"] == "divergence" else "unexpected_both_" + w
    return "unexpected_divergence"


def grade(results):
    """Pre-registered hypotheses H1-H5 (PREREG-runas.md section 4)."""
    def fam(f, kind):
        return [x for x in results if x["family"] == f and x["kind"] == kind]

    def all_ok(xs):
        return bool(xs) and all(x["verdict"] == "as_predicted" and x["stable"] for x in xs)

    controls = [x for x in results if x["kind"] == "control"]
    a_allowed = [x for x in fam("A", "divergence") if cls(x["rs"]["decision"]) == ALLOW]
    h5 = bool(a_allowed) and all(
        (x["rs"]["probe"] or {}).get("uid") == 2001 and (x["rs"]["probe"] or {}).get("egid") == 3500
        for x in a_allowed)
    return {
        "H1_A_self_negation_ignored": all_ok(fam("A", "divergence")),
        "H1_A_count": "%d/%d" % (sum(x["verdict"] == "as_predicted" for x in fam("A", "divergence")),
                                 len(fam("A", "divergence"))),
        "H2_B_group_negation_ignored": all_ok(fam("B", "divergence")),
        "H2_B_count": "%d/%d" % (sum(x["verdict"] == "as_predicted" for x in fam("B", "divergence")),
                                 len(fam("B", "divergence"))),
        "H3_C_restrictive": all_ok(fam("C", "divergence")),
        "H4_controls_agree": bool(controls) and all(
            cls(x["ws"]["decision"]) == cls(x["rs"]["decision"]) for x in controls),
        "H5_A_gain_is_self_uid_with_group": h5,
    }


def render_md(env, results, grades):
    lines = ["# sudo-policy-diff study 2: Runas negation cases", "",
             "sudo: %s" % (env.get("dpkg", "").strip().replace("\n", "; ")), "",
             "| id | kind | policy rule | request | sudo | sudo-rs | predicted | verdict | stable |",
             "|---|---|---|---|---|---|---|---|---|"]
    for x in results:
        rq = x["request"]
        req = "%s%s%s" % (rq["invoker"], (" -u " + rq["runas_user"]) if rq["runas_user"] else "",
                          (" -g " + rq["runas_group"]) if rq["runas_group"] else "")
        lines.append("| %s | %s | `%s` | `%s` | %s | %s | %s/%s | %s | %s |" % (
            x["id"], x["kind"], " ; ".join(x["lines"]), req, x["ws"]["decision"],
            x["rs"]["decision"], x["expect_ws"], x["expect_rs"], x["verdict"], x["stable"]))
    lines += ["", "## Hypotheses (raw)", ""]
    for k, v in grades.items():
        lines.append("- %s: %s" % (k, v))
    return "\n".join(lines) + "\n"


def main(argv=None):
    import sudodiff as S
    import sudoers_gen as G
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="/out")
    ap.add_argument("--repeats", type=int, default=2)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("must run as root inside a disposable container")
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    info, pw = S.setup()
    host = info["hostname"]
    pre = S.preflight(pw, host)
    info["preflight"] = pre
    S.write_json(os.path.join(a.out, "env.json"), info)
    if not pre["ok"]:
        S.write_json(os.path.join(a.out, "summary.json"),
                     {"status": "preflight_failed", "preflight": pre})
        print(json.dumps(pre, indent=1, default=str))
        return 2
    results = []
    for c in CASES:
        S.install_policy(G.render_policy(c["lines"], host))
        vis = S.visudo_check()
        runs = []
        for _ in range(max(1, a.repeats)):
            res, f = S.eval_both(c["request"], pw)
            runs.append((res, f))
        res, f = runs[0]
        sig = [(r["ws"]["decision"], r["rs"]["decision"]) for r, _ in runs]
        slim = S.slim(res, c["request"])
        x = dict(c)
        x.update({"ws": slim["ws"], "rs": slim["rs"], "findings": f, "visudo": vis,
                  "argv_rs": G.sudo_argv(S.RS, c["request"], "-n"),
                  "stable": len(set(sig)) == 1,
                  "verdict": judge(c, res["ws"]["decision"], res["rs"]["decision"])})
        results.append(x)
        print("%-4s %-10s ws=%-16s rs=%-16s %s" % (c["id"], c["kind"], res["ws"]["decision"],
                                                    res["rs"]["decision"], x["verdict"]))
    grades = grade(results)
    S.write_json(os.path.join(a.out, "results.json"), results)
    S.write_json(os.path.join(a.out, "summary.json"),
                 {"status": "ok", "cases": len(results), "grades": grades,
                  "minutes": (time.time() - t0) / 60.0})
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(render_md(info, results, grades))
    print(json.dumps(grades, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
