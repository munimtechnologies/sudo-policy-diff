# SPDX-License-Identifier: Apache-2.0
import unittest

import runas_cases as R
import sudoers_gen as G


def fake(case, ws, rs, uid=2001, egid=3500, stable=True):
    x = dict(case)
    probe = {"uid": uid, "egid": egid}
    x.update({"ws": {"decision": ws, "probe": probe if ws.startswith("ALLOW") else None},
              "rs": {"decision": rs, "probe": probe if rs.startswith("ALLOW") else None},
              "stable": stable, "verdict": R.judge(case, ws, rs)})
    return x


def dec(c):
    return "ALLOW_NOPASSWD" if c == R.ALLOW else "DENY"


class TestCases(unittest.TestCase):
    def test_ids_unique(self):
        ids = [c["id"] for c in R.CASES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_shapes(self):
        users = {u[0] for u in G.USERS} | {"root"}
        groups = {g[0] for g in G.GROUPS} | {"root"}
        for c in R.CASES:
            self.assertIn(c["family"], "ABCDE")
            self.assertIn(c["kind"], ("divergence", "control"))
            self.assertIn(c["expect_ws"], (R.ALLOW, R.DENY))
            self.assertIn(c["expect_rs"], (R.ALLOW, R.DENY))
            if c["kind"] == "divergence":
                self.assertNotEqual(c["expect_ws"], c["expect_rs"], c["id"])
            else:
                self.assertEqual(c["expect_ws"], c["expect_rs"], c["id"])
            rq = c["request"]
            self.assertIn(rq["invoker"], G.INVOKERS)
            if rq["runas_user"]:
                self.assertIn(rq["runas_user"], users)
            if rq["runas_group"]:
                self.assertIn(rq["runas_group"], groups)
            self.assertTrue(any("NOPASSWD: " + R.PROBE in ln for ln in c["lines"]), c["id"])
            txt = G.render_policy(c["lines"], "box")
            self.assertIn("Defaults timestamp_timeout=0", txt)

    def test_family_counts(self):
        div = {f: sum(1 for c in R.CASES if c["family"] == f and c["kind"] == "divergence")
               for f in "ABC"}
        self.assertEqual(div, {"A": 6, "B": 3, "C": 2})
        perm = [c for c in R.CASES if c["kind"] == "divergence" and c["family"] in "AB"]
        self.assertTrue(all(c["expect_ws"] == R.DENY and c["expect_rs"] == R.ALLOW for c in perm))

    def test_argv(self):
        c = [x for x in R.CASES if x["id"] == "A2"][0]
        self.assertEqual(G.sudo_argv("/usr/bin/sudo-rs", c["request"], "-n"),
                         ["/usr/bin/sudo-rs", "-n", "-u", "alice", "-g", "svcgrp", R.PROBE])
        c = [x for x in R.CASES if x["id"] == "A1"][0]
        self.assertEqual(G.target_user(c["request"]), "alice")


class TestJudgeGrade(unittest.TestCase):
    def test_judge(self):
        a1 = R.CASES[0]
        self.assertEqual(R.judge(a1, "DENY", "ALLOW_NOPASSWD"), "as_predicted")
        self.assertEqual(R.judge(a1, "DENY", "DENY"), "unexpected_agree")
        self.assertEqual(R.judge(a1, "ALLOW_PW_INVOKER", "DENY"), "unexpected_divergence")
        ctrl = [c for c in R.CASES if c["kind"] == "control" and c["expect_ws"] == R.ALLOW][0]
        self.assertEqual(R.judge(ctrl, "DENY", "DENY"), "unexpected_both_DENY")

    def test_grade_all_predicted(self):
        res = [fake(c, dec(c["expect_ws"]), dec(c["expect_rs"])) for c in R.CASES]
        g = R.grade(res)
        self.assertTrue(g["H1_A_self_negation_ignored"])
        self.assertEqual(g["H1_A_count"], "6/6")
        self.assertTrue(g["H2_B_group_negation_ignored"])
        self.assertTrue(g["H3_C_restrictive"])
        self.assertTrue(g["H4_controls_agree"])
        self.assertTrue(g["H5_A_gain_is_self_uid_with_group"])

    def test_grade_none(self):
        res = [fake(c, "DENY", "DENY") for c in R.CASES]
        g = R.grade(res)
        self.assertFalse(g["H1_A_self_negation_ignored"])
        self.assertEqual(g["H1_A_count"], "0/6")
        self.assertFalse(g["H5_A_gain_is_self_uid_with_group"])
        self.assertTrue(g["H4_controls_agree"])  # both DENY still counts as agreement

    def test_unstable_fails(self):
        res = [fake(c, dec(c["expect_ws"]), dec(c["expect_rs"]), stable=False) for c in R.CASES]
        self.assertFalse(R.grade(res)["H1_A_self_negation_ignored"])

    def test_render(self):
        res = [fake(c, dec(c["expect_ws"]), dec(c["expect_rs"])) for c in R.CASES]
        md = R.render_md({"dpkg": "sudo 1\nsudo-rs 2\n"}, res, R.grade(res))
        self.assertIn("| A1 |", md)
        self.assertIn("sudo 1; sudo-rs 2", md)
        self.assertIn("H3_C_restrictive", md)


if __name__ == "__main__":
    unittest.main()
