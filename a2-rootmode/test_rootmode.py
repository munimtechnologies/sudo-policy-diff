# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""Unit tests for the amendment A2 runner (pure parts only; no sudo needed)."""

import unittest

import rootmode as M


def synthetic_records(rs_version="0.2.14"):
    """Every case behaves exactly as predicted (used to test the grading wiring)."""
    recs = []
    for c in M.unify_cases():
        rec = dict(c)
        rec["modes"] = {}
        na = "fqdn" if c["needs"] == "fqdn" else None
        lines, rq = M.run_mode_plan(c)
        if na or lines is None:
            rec["modes"]["run"] = {"na": na or rq}
        else:
            def mk(dec, is_rs):
                probe = None
                if dec == M.ALLOW:
                    if c["study"] == "hosts":
                        probe = {"uid": M.ALICE_UID}
                    else:
                        probe = {"uid": 0, "egid": M.SVCGRP_GID}
                return {"decision": dec, "probe": probe, "stable": True}
            rec["modes"]["run"] = {"impl": {"ws": mk(c["expect_ws"], False),
                                            "rs-" + rs_version: mk(c["expect_rs"], True)}}
        if c["study"] == "hosts":
            if na:
                rec["modes"]["list"] = {"na": na}
            else:
                rec["modes"]["list"] = {"impl": {
                    "ws": {"decision": c["expect_ws"], "probe": None, "stable": True},
                    "rs-" + rs_version: {"decision": c["expect_rs"], "probe": None,
                                         "stable": True}}}
        recs.append(rec)
    return recs


class TestSwap(unittest.TestCase):
    def test_rule_swaps(self):
        self.assertEqual(
            M.swap_text("alice ALL = (ALL, !alice : svcgrp) NOPASSWD: /usr/local/bin/probe"),
            "root ALL = (ALL, !root : svcgrp) NOPASSWD: /usr/local/bin/probe")
        self.assertEqual(M.swap_text("alice ALL = (ALL, !#2001 : svcgrp) NOPASSWD: x"),
                         "root ALL = (ALL, !#0 : svcgrp) NOPASSWD: x")
        self.assertEqual(M.swap_text("alice ALL = (root : team) NOPASSWD: x"),
                         "root ALL = (alice : team) NOPASSWD: x")
        self.assertEqual(M.swap_text("Runas_Alias NOTME = ALL, !alice"),
                         "Runas_Alias NOTME = ALL, !root")
        self.assertEqual(M.swap_text("(ALL, !%wheel : svcgrp)"), "(ALL, !%wheel : svcgrp)")
        self.assertEqual(M.swap_text("/root/bin/x /usr/bin/rootish aliceX"),
                         "/root/bin/x /usr/bin/rootish aliceX")
        self.assertEqual(M.swap_text("User_Alias BLOCKED = alice, +contractors"),
                         "User_Alias BLOCKED = root, +contractors")

    def test_swap_is_an_involution_on_all_cases(self):
        for c in M.unify_cases():
            for line in c["lines"]:
                self.assertEqual(M.swap_text(M.swap_text(line)), line, line)

    def test_every_rule_names_root_after_swap(self):
        for c in M.unify_cases():
            lines, rq = M.run_mode_plan(c)
            if lines is None:
                continue
            self.assertEqual(rq["invoker"], "root")
            self.assertNotIn("alice ALL", "\n".join(lines))

    def test_requests(self):
        self.assertEqual(M.swap_request({"invoker": "alice", "runas_user": None,
                                         "runas_group": None}),
                         {"invoker": "root", "runas_user": "alice", "runas_group": None})
        self.assertEqual(M.swap_request({"invoker": "alice", "runas_user": None,
                                         "runas_group": "svcgrp"}),
                         {"invoker": "root", "runas_user": None, "runas_group": "svcgrp"})
        self.assertEqual(M.swap_request({"invoker": "alice", "runas_user": "alice",
                                         "runas_group": "team"}),
                         {"invoker": "root", "runas_user": "root", "runas_group": "team"})
        self.assertEqual(M.swap_request({"invoker": "alice", "runas_user": "bob",
                                         "runas_group": "team"})["runas_user"], "bob")
        self.assertIsNone(M.swap_request({"invoker": "bob", "runas_user": None,
                                          "runas_group": None}))

    def test_run_mode_plan_na(self):
        by = {(c["study"], c["id"]): c for c in M.unify_cases()}
        for cid in ("E1", "E2"):
            lines, why = M.run_mode_plan(by[("runas", cid)])
            self.assertIsNone(lines)
            self.assertTrue(why)
        lines, why = M.run_mode_plan(by[("hosts", "C7")])
        self.assertIsNone(lines)
        lines, rq = M.run_mode_plan(by[("runas", "A9")])
        self.assertEqual(rq["runas_user"], "alice")
        self.assertEqual(lines, ["root ALL = (ALL, !root : svcgrp) NOPASSWD: /usr/local/bin/probe"])


class TestCases(unittest.TestCase):
    def test_counts(self):
        cs = M.unify_cases()
        self.assertEqual(sum(c["study"] == "hosts" for c in cs), 23)
        self.assertEqual(sum(c["study"] == "runas" for c in cs), 26)
        self.assertEqual(len({(c["study"], c["id"]) for c in cs}), 49)


class TestArgvAndParsing(unittest.TestCase):
    def test_argv(self):
        rq = {"invoker": "root", "runas_user": "alice", "runas_group": "svcgrp"}
        self.assertEqual(M.run_argv("/b/sudo", rq),
                         ["/b/sudo", "-n", "-u", "alice", "-g", "svcgrp", M.PROBE])
        self.assertEqual(M.list_argv("/b/sudo", {"invoker": "alice"}),
                         ["/b/sudo", "-n", "-l", "-U", "alice", "-u", "root", M.PROBE])

    def test_list_decision(self):
        self.assertEqual(M.list_decision(0, "/usr/local/bin/probe\n"), M.ALLOW)
        self.assertEqual(M.list_decision(1, ""), M.DENY)
        self.assertEqual(M.list_decision(0, "User alice may run the following\n"), M.DENY)
        self.assertEqual(M.list_decision(1, "/usr/local/bin/probe\n"), M.DENY)

    def test_parse_probe(self):
        rec = M.parse_probe("noise\n" + M.PROBE_PREFIX + '{"uid": 0, "egid": 3500}\n')
        self.assertEqual(rec["egid"], 3500)
        self.assertIsNone(M.parse_probe("nothing"))

    def test_probe_script_compiles(self):
        compile(M.probe_script(), "probe", "exec")

    def test_render(self):
        t = M.render(["alice ALL, !{HOSTCASE} = x", "a {SHORT} {HOST}"], "db1.example.org",
                     "db1.example.orG", rootline=True)
        self.assertIn(M.ROOTLINE, t)
        self.assertIn("!db1.example.orG", t)
        self.assertIn("a db1 db1.example.org", t)


class TestGrading(unittest.TestCase):
    def test_all_as_predicted(self):
        recs = synthetic_records()
        g = M.summarize(recs, ["0.2.14"])
        h = g["hosts/run/sudo-rs-0.2.14"]
        self.assertIs(h["H1_dropped_alias_fail_open"], True)
        self.assertIs(h["H2_case_silent_fail_open"], True)
        self.assertEqual(h["H3_fqdn_silent_fail_open"], "n/a")
        self.assertIs(h["H5_controls_agree"], True)
        self.assertIs(h["H6_gain_is_root"], True)
        hl = g["hosts/list/sudo-rs-0.2.14"]
        self.assertIs(hl["H1_dropped_alias_fail_open"], True)
        self.assertEqual(hl["H1_count"], "6/6")
        r = g["runas/run/sudo-rs-0.2.14"]
        self.assertIs(r["H1_A_self_negation_ignored"], True)
        self.assertIs(r["H2_B_group_negation_ignored"], True)
        self.assertIs(r["H3_C_restrictive"], True)
        self.assertIs(r["H4_controls_agree"], True)
        self.assertIs(r["H5_A_gain_is_self_uid_with_group"], True)
        self.assertEqual(r["not_run"], ["E1", "E2"])
        ag = M.agreement(recs, ["0.2.14"])
        self.assertEqual(ag["differ"], 0)
        self.assertGreater(ag["same"], 30)
        M.render_md({"rs": {}}, recs, g, ag, ["0.2.14"])

    def test_refuted(self):
        recs = synthetic_records()
        for rec in recs:
            if rec["study"] == "runas" and rec["family"] == "A" and rec["kind"] == "divergence":
                rec["modes"]["run"]["impl"]["rs-0.2.14"] = {"decision": M.DENY, "probe": None,
                                                            "stable": True}
        r = M.summarize(recs, ["0.2.14"])["runas/run/sudo-rs-0.2.14"]
        self.assertIs(r["H1_A_self_negation_ignored"], False)
        self.assertEqual(r["H1_A_count"], "0/6")
        self.assertIs(r["H5_A_gain_is_self_uid_with_group"], False)


if __name__ == "__main__":
    unittest.main()
