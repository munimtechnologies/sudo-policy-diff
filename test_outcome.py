# SPDX-License-Identifier: Apache-2.0
import json
import unittest

import outcome as O


def probe(**kw):
    p = {"tag": "probe", "exe": "/usr/local/bin/probe", "argv": [], "uid": 0, "euid": 0,
         "gid": 0, "egid": 0, "groups": [0], "cwd": "/", "umask": 0o22,
         "env": {"PATH": "/usr/bin", "HOME": "/root", "USER": "root"}}
    p.update(kw)
    return p


def kinds(fs):
    return sorted((f["kind"], f["direction"]) for f in fs)


class TestParse(unittest.TestCase):
    def test_parse_probe(self):
        rec = {"tag": "probe", "uid": 0}
        out = "noise\n" + O.PROBE_PREFIX + json.dumps(rec) + "\nmore\n"
        self.assertEqual(O.parse_probe(out), rec)
        self.assertIsNone(O.parse_probe("nothing here"))
        self.assertIsNone(O.parse_probe(O.PROBE_PREFIX + "{broken"))
        self.assertIsNone(O.parse_probe(O.PROBE_PREFIX + "[1, 2]"))
        self.assertIsNone(O.parse_probe(None))

    def test_short_err(self):
        e = "[sudo] password for alice: \nSorry, user alice is not allowed\n\n"
        self.assertEqual(O.short_err(e), "Sorry, user alice is not allowed")

    def test_decide(self):
        p = probe()
        self.assertEqual(O.decide([{"stage": "nopass", "probe": None},
                                   {"stage": "pw_invoker", "probe": p}]),
                         ("ALLOW_PW_INVOKER", p))
        self.assertEqual(O.decide([{"stage": "nopass", "probe": p}]), ("ALLOW_NOPASSWD", p))
        self.assertEqual(O.decide([{"stage": "nopass", "probe": None}]), ("DENY", None))


class TestCompare(unittest.TestCase):
    def test_identical(self):
        p = probe()
        self.assertEqual(O.compare("ALLOW_NOPASSWD", p, "ALLOW_NOPASSWD", dict(p), {}), [])

    def test_decision_permissive(self):
        fs = O.compare("DENY", None, "ALLOW_NOPASSWD", probe(), {})
        self.assertEqual(kinds(fs), [("DECISION", "permissive")])
        self.assertTrue(O.is_security(fs[0]))
        self.assertEqual(fs[0]["detail"], "ws=DENY rs=ALLOW_NOPASSWD")

    def test_decision_restrictive(self):
        fs = O.compare("ALLOW_PW_INVOKER", probe(), "DENY", None, {})
        self.assertEqual(kinds(fs), [("DECISION", "restrictive")])
        self.assertFalse(O.is_security(fs[0]))

    def test_auth(self):
        fs = O.compare("ALLOW_PW_ROOT", probe(), "ALLOW_PW_INVOKER", probe(), {})
        self.assertEqual(kinds(fs), [("AUTH", "permissive")])
        fs = O.compare("ALLOW_PW_ROOT", probe(), "ALLOW_PW_TARGET", probe(), {})
        self.assertEqual(kinds(fs), [("AUTH", "unclear")])
        self.assertTrue(O.is_security(fs[0]))

    def test_identity(self):
        fs = O.compare("ALLOW_NOPASSWD", probe(uid=2002, euid=2002),
                       "ALLOW_NOPASSWD", probe(), {})
        self.assertEqual(kinds(fs), [("IDENTITY", "permissive"), ("IDENTITY", "permissive")])
        fs = O.compare("ALLOW_NOPASSWD", probe(gid=3500), "ALLOW_NOPASSWD", probe(gid=3001), {})
        self.assertEqual(kinds(fs), [("IDENTITY", "unclear")])

    def test_groups(self):
        fs = O.compare("ALLOW_NOPASSWD", probe(groups=[0]), "ALLOW_NOPASSWD",
                       probe(groups=[0, 3002]), {})
        self.assertEqual(kinds(fs), [("GROUPS", "permissive")])
        fs = O.compare("ALLOW_NOPASSWD", probe(groups=[0, 1]), "ALLOW_NOPASSWD",
                       probe(groups=[0, 2]), {})
        self.assertEqual(kinds(fs), [("GROUPS", "unclear")])

    def test_exec(self):
        fs = O.compare("ALLOW_NOPASSWD", probe(), "ALLOW_NOPASSWD",
                       probe(tag="evil-alice", exe="/home/alice/evil/probe"), {})
        self.assertEqual(kinds(fs), [("EXEC", "unclear")])
        fs = O.compare("ALLOW_NOPASSWD", probe(exe="/dev/fd/3"), "ALLOW_NOPASSWD", probe(), {})
        self.assertEqual(kinds(fs), [("EXEC_PATH", "info")])
        self.assertFalse(O.is_security(fs[0]))

    def test_umask(self):
        fs = O.compare("ALLOW_NOPASSWD", probe(umask=0o77), "ALLOW_NOPASSWD", probe(umask=0o22), {})
        self.assertEqual(kinds(fs), [("UMASK", "permissive")])
        fs = O.compare("ALLOW_NOPASSWD", probe(umask=0o22), "ALLOW_NOPASSWD", probe(umask=0o77), {})
        self.assertEqual(kinds(fs), [("UMASK", "restrictive")])
        fs = O.compare("ALLOW_NOPASSWD", probe(umask=0o02), "ALLOW_NOPASSWD", probe(umask=0o20), {})
        self.assertEqual(kinds(fs), [("UMASK", "unclear")])

    def test_env(self):
        ue = {"LD_PRELOAD": "/tmp/user-ld.so", "TERM": "dumb", "PATH": "/home/alice/evil"}
        ws = probe(env={"PATH": "/usr/bin"})
        rs = probe(env={"PATH": "/home/alice/evil", "LD_PRELOAD": "/tmp/user-ld.so",
                        "TERM": "dumb", "MAIL": "/var/mail/root"})
        fs = O.compare("ALLOW_NOPASSWD", ws, "ALLOW_NOPASSWD", rs, ue)
        self.assertEqual(kinds(fs), [("ENV", "permissive"), ("ENV", "permissive"),
                                     ("ENV_BASELINE", "info"), ("ENV_BENIGN", "permissive")])
        details = {f["kind"]: f["detail"] for f in fs if f["kind"] == "ENV_BASELINE"}
        self.assertEqual(details["ENV_BASELINE"], "MAIL")
        sec = [f for f in fs if O.is_security(f)]
        self.assertEqual(sorted(f["detail"] for f in sec), ["LD_PRELOAD", "PATH"])

    def test_env_restrictive(self):
        ue = {"FOO": "user-foo"}
        fs = O.compare("ALLOW_NOPASSWD", probe(env={"FOO": "user-foo"}),
                       "ALLOW_NOPASSWD", probe(env={}), ue)
        self.assertEqual(kinds(fs), [("ENV", "restrictive")])

    def test_key_and_tally(self):
        fs = [O.finding("ENV", "permissive", "FOO"), O.finding("ENV", "permissive", "BAR"),
              O.finding("DECISION", "restrictive", "x")]
        self.assertEqual(O.key(fs[0]), ("ENV", "permissive", "FOO"))
        self.assertEqual(O.tally(fs), {"DECISION/restrictive": 1, "ENV/permissive": 2})


class TestGrade(unittest.TestCase):
    def test_grade(self):
        s = {"finding_counts": {"DECISION/restrictive": 4, "ENV/permissive": 1},
             "control": {"requests": 300, "noisy": 0}, "preflight_ok": True,
             "visudo": {"ws_ok/rs_ok": 90, "ws_ok/rs_bad": 10}}
        g = O.grade(s)
        self.assertTrue(g["P1_control_clean"])
        self.assertTrue(g["P2_preflight_ok"])
        self.assertTrue(g["P3_any_decision_divergence"])
        self.assertFalse(g["P4_permissive_decision_or_auth"])
        self.assertTrue(g["P5_permissive_env"])
        self.assertFalse(g["P6_identity_or_groups"])
        self.assertTrue(g["P7_rs_rejects_5pct"])


if __name__ == "__main__":
    unittest.main()
