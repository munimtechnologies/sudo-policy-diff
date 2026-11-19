# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
import unittest

import hostcases as H


def fake(case, ws, rs, uid=0, stable=True):
    x = dict(case)
    probe = {"uid": uid}
    x.update({"ws": {"decision": ws, "probe": probe if ws.startswith("ALLOW") else None},
              "rs": {"decision": rs, "probe": probe if rs.startswith("ALLOW") else None,
                     "err": ""},
              "stable": stable, "verdict": H.judge(case, ws, rs)})
    return x


def dec(c):
    return "ALLOW_NOPASSWD" if c == H.ALLOW else "DENY"


class TestCases(unittest.TestCase):
    def test_ids_unique(self):
        ids = [c["id"] for c in H.CASES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_shapes(self):
        for c in H.CASES:
            self.assertIn(c["family"], "HSRCKF")
            self.assertIn(c["kind"], ("divergence", "control"))
            self.assertIn(c["invoker"], [u[0] for u in H.USERS])
            if c["kind"] == "divergence":
                self.assertNotEqual(c["expect_ws"], c["expect_rs"], c["id"])
            else:
                self.assertEqual(c["expect_ws"], c["expect_rs"], c["id"])
            txt = H.render(c["lines"], "box7f.sudodiff.test" if c["needs"] == "fqdn"
                           else "box7f", "box7F")
            self.assertIn("Defaults timestamp_timeout=0", txt)
            self.assertNotIn("{", txt, c["id"])
            self.assertIn("NOPASSWD", txt)

    def test_fqdn_cases_last(self):
        needs = [c["needs"] == "fqdn" for c in H.CASES]
        first = needs.index(True)
        self.assertTrue(all(needs[first:]))

    def test_family_counts(self):
        div = {f: sum(1 for c in H.CASES if c["family"] == f and c["kind"] == "divergence")
               for f in "HSRFK"}
        self.assertEqual(div, {"H": 6, "S": 2, "R": 3, "F": 3, "K": 1})
        for c in H.CASES:
            if c["family"] in "HSK" and c["kind"] == "divergence":
                self.assertEqual((c["expect_ws"], c["expect_rs"]), (H.DENY, H.ALLOW))
            if c["family"] == "R":
                self.assertEqual((c["expect_ws"], c["expect_rs"]), (H.ALLOW, H.DENY))


class TestHelpers(unittest.TestCase):
    def test_flip_case(self):
        self.assertEqual(H.flip_case("3f2a9c1b7d4e"), "3f2a9c1b7d4E")
        self.assertEqual(H.flip_case("abc123"), "abC123")
        self.assertIsNone(H.flip_case("123456"))
        self.assertIsNone(H.flip_case("a12345"))     # only letter is the first char
        self.assertIsNone(H.flip_case("Abc"))        # starts upper-case
        out = H.flip_case("a1b2")
        self.assertEqual(out, "a1B2")
        self.assertIsNone(H.ALIAS_RE.match(out))

    def test_short_and_render(self):
        self.assertEqual(H.short_of("db01.example.com"), "db01")
        self.assertEqual(H.short_of("db01"), "db01")
        t = H.render(["alice ALL, !{SHORT} = x", "y {HOST} {HOSTCASE}"], "db01.ex.test", "dB01")
        self.assertIn("alice ALL, !db01 = x", t)
        self.assertIn("y db01.ex.test dB01", t)
        self.assertIn("NO_CASE_VARIANT", H.render(["{HOSTCASE}"], "h"))

    def test_parse_probe(self):
        self.assertEqual(H.parse_probe("noise\n" + H.PROBE_PREFIX + '{"uid": 0}\n'), {"uid": 0})
        self.assertIsNone(H.parse_probe("nothing"))
        self.assertIsNone(H.parse_probe(H.PROBE_PREFIX + "{bad"))

    def test_argv(self):
        self.assertEqual(H.argv_for(H.RS), ["/usr/bin/sudo-rs", "-n", H.PROBE])

    def test_probe_script_compiles(self):
        compile(H.probe_script(), "probe", "exec")


class TestJudgeGrade(unittest.TestCase):
    def test_judge(self):
        h1 = H.CASES[0]
        self.assertEqual(H.judge(h1, "DENY", "ALLOW_NOPASSWD"), "as_predicted")
        self.assertEqual(H.judge(h1, "DENY", "DENY"), "unexpected_agree")
        self.assertEqual(H.judge(h1, "ALLOW_NOPASSWD", "DENY"), "unexpected_divergence")
        self.assertEqual(H.judge(h1, H.NA, H.NA), "n/a")
        c3 = [c for c in H.CASES if c["id"] == "C3"][0]
        self.assertEqual(H.judge(c3, "DENY", "DENY"), "unexpected_both_DENY")

    def test_grade_all_predicted(self):
        res = [fake(c, dec(c["expect_ws"]), dec(c["expect_rs"])) for c in H.CASES]
        g = H.grade(res)
        self.assertIs(g["H1_dropped_alias_fail_open"], True)
        self.assertEqual(g["H1_count"], "6/6")
        self.assertIs(g["H2_case_silent_fail_open"], True)
        self.assertIs(g["H3_fqdn_silent_fail_open"], True)
        self.assertIs(g["H4_restrictive_mirrors"], True)
        self.assertEqual(g["H4_count"], "3/3")
        self.assertTrue(g["H5_controls_agree"])
        self.assertTrue(g["H6_gain_is_root"])
        self.assertEqual(g["K1_exploratory"], "as_predicted")

    def test_grade_none(self):
        res = [fake(c, "DENY", "DENY") for c in H.CASES]
        g = H.grade(res)
        self.assertIs(g["H1_dropped_alias_fail_open"], False)
        self.assertEqual(g["H1_count"], "0/6")
        self.assertFalse(g["H6_gain_is_root"])

    def test_grade_fqdn_na(self):
        res = []
        for c in H.CASES:
            if c["needs"] == "fqdn":
                res.append(H.na_result(c, "no sethostname"))
            else:
                res.append(fake(c, dec(c["expect_ws"]), dec(c["expect_rs"])))
        g = H.grade(res)
        self.assertEqual(g["H3_fqdn_silent_fail_open"], "n/a")
        self.assertIs(g["H1_dropped_alias_fail_open"], True)
        self.assertTrue(g["H5_controls_agree"])

    def test_unstable_fails(self):
        res = [fake(c, dec(c["expect_ws"]), dec(c["expect_rs"]), stable=False) for c in H.CASES]
        self.assertIs(H.grade(res)["H1_dropped_alias_fail_open"], False)

    def test_render_md(self):
        res = [fake(c, dec(c["expect_ws"]), dec(c["expect_rs"])) for c in H.CASES]
        md = H.render_md({"dpkg": "sudo 1\nsudo-rs 2\n", "hostname": "h"}, res, H.grade(res))
        self.assertIn("| H1 |", md)
        self.assertIn("sudo 1; sudo-rs 2", md)
        self.assertIn("H3_fqdn_silent_fail_open", md)


if __name__ == "__main__":
    unittest.main()
