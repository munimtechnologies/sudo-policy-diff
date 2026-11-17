# SPDX-License-Identifier: Apache-2.0
import random
import re
import unittest

import sudoers_gen as G

FORBIDDEN = ("NOEXEC", "INTERCEPT", "sudoedit", "sha256:", "env_delete", "^", "$", "LDAP")
WILD = re.compile(r"[*?\[]")


def cmnd_items(line):
    """Command items of a user spec or Cmnd_Alias line (rough split, test only)."""
    rhs = line.split("=", 1)[1]
    rhs = re.sub(r"\([^)]*\)", " ", rhs)  # drop Runas specs (they contain commas)
    items = []
    for part in rhs.split(","):
        toks = part.split()
        # drop CWD and tags
        toks = [t for t in toks if not t.endswith(":") and not t.startswith("CWD=")]
        joined = " ".join(toks)
        if joined:
            items.append(joined)
    return items


class TestPolicy(unittest.TestCase):
    def policies(self, n=400, seed=7):
        rng = random.Random(seed)
        return [G.generate_policy(rng) for _ in range(n)]

    def test_deterministic(self):
        self.assertEqual(self.policies(50, 3), self.policies(50, 3))

    def test_header_and_host(self):
        lines = ["alice %s = ALL" % G.HOST_TOKEN]
        txt = G.render_policy(lines, "box1")
        self.assertTrue(txt.startswith(G.HEADER[0]))
        self.assertIn("Defaults timestamp_timeout=0", txt)
        self.assertIn("alice box1 = ALL", txt)
        self.assertNotIn(G.HOST_TOKEN, txt)
        self.assertTrue(txt.endswith("\n"))

    def test_no_unsupported_features(self):
        for lines in self.policies():
            for ln in lines:
                for bad in FORBIDDEN:
                    self.assertNotIn(bad, ln, ln)
                self.assertNotIn("timestamp_timeout", ln)

    def test_argument_wildcards_only_final_star(self):
        seen_args = 0
        for lines in self.policies():
            for ln in lines:
                if ln.startswith("Defaults") or ln.startswith(("User_Alias", "Runas_Alias", "Host_Alias")):
                    continue
                for item in cmnd_items(ln):
                    toks = item.lstrip("!").split()
                    args = toks[1:]
                    if args:
                        seen_args += 1
                    for i, t in enumerate(args):
                        if WILD.search(t):
                            self.assertEqual(t, "*", ln)
                            self.assertEqual(i, len(args) - 1, ln)
        self.assertGreater(seen_args, 20)

    def test_aliases_defined_before_use(self):
        for lines in self.policies():
            defined = set()
            for ln in lines:
                m = re.match(r"(User|Runas|Host|Cmnd)_Alias (\w+) =", ln)
                if m:
                    defined.add(m.group(2))
                    continue
                for name in ("UA", "RA", "HA", "CA"):
                    if re.search(r"(?<![A-Za-z_])%s(?![A-Za-z_])" % name, ln):
                        self.assertIn(name, defined, ln)

    def test_directories_have_no_args(self):
        for lines in self.policies():
            for ln in lines:
                for d in G.DIR_PATHS:
                    idx = ln.find(d + " ")
                    if idx >= 0:
                        rest = ln[idx + len(d) + 1:]
                        self.assertTrue(rest == "" or rest.startswith(","), ln)

    def test_policy_shape(self):
        for lines in self.policies(100):
            specs = [l for l in lines if not l.startswith(("Defaults", "User_Alias",
                                                           "Runas_Alias", "Host_Alias", "Cmnd_Alias"))]
            self.assertGreaterEqual(len(specs), 1)
            for s in specs:
                self.assertIn(" = ", s)


class TestRequests(unittest.TestCase):
    def reqs(self, n=500):
        rng = random.Random(11)
        return [G.generate_request(rng) for _ in range(n)]

    def test_request_fields(self):
        for r in self.reqs():
            self.assertIn(r["invoker"], G.INVOKERS)
            self.assertIsInstance(r["args"], list)
            self.assertIsInstance(r["env"], dict)
            self.assertTrue(r["cwd"].startswith("/"))

    def test_argv(self):
        req = {"invoker": "bob", "runas_user": "svc", "runas_group": "svcgrp",
               "cmd": "{home}/bin/zz", "args": ["a", ""], "cwd": "/", "env": {},
               "cmdline_env": ["PATH={home}/evil:/usr/bin:/bin"], "preserve_env": True,
               "chdir": "/tmp"}
        self.assertEqual(G.sudo_argv("/usr/bin/sudo-rs", req, "-n"), [
            "/usr/bin/sudo-rs", "-n", "-u", "svc", "-g", "svcgrp", "-E", "-D", "/tmp",
            "PATH=/home/bob/evil:/usr/bin:/bin", "/home/bob/bin/zz", "a", ""])

    def test_argv_minimal(self):
        req = {"invoker": "alice", "runas_user": None, "runas_group": None,
               "cmd": "probe", "args": [], "cwd": "/", "env": {}, "cmdline_env": [],
               "preserve_env": False, "chdir": None}
        self.assertEqual(G.sudo_argv("/usr/bin/sudo.ws", req, "-S"),
                         ["/usr/bin/sudo.ws", "-S", "probe"])

    def test_user_env(self):
        req = {"invoker": "alice", "env": {"PATH": "{home}/evil:/usr/bin", "FOO": "user-foo"},
               "cmdline_env": ["FOO=cl-foo", "HOME=/tmp/cl-home"]}
        ue = G.user_env(req)
        self.assertEqual(ue["PATH"], "/home/alice/evil:/usr/bin")
        self.assertEqual(ue["FOO"], "cl-foo")
        self.assertEqual(ue["HOME"], "/tmp/cl-home")
        self.assertEqual(ue["USER"], "alice")
        ie = G.invoker_env(req)
        self.assertEqual(ie["FOO"], "user-foo")
        self.assertEqual(ie["HOME"], "/home/alice")

    def test_target_user(self):
        b = {"invoker": "carol", "runas_group": None}
        self.assertEqual(G.target_user(dict(b, runas_user=None)), "root")
        self.assertEqual(G.target_user(dict(b, runas_user=None, runas_group="ops")), "carol")
        self.assertEqual(G.target_user(dict(b, runas_user="#2500")), "svc")
        self.assertIsNone(G.target_user(dict(b, runas_user="#4242")))
        self.assertEqual(G.target_user(dict(b, runas_user="bob")), "bob")

    def test_probe_script(self):
        s = G.probe_script("probe4")
        self.assertTrue(s.startswith("#!/usr/bin/python3 -I\n"))
        self.assertIn("'probe4'", s)
        self.assertIn(repr(G.PROBE_PREFIX), s)
        compile(s, "probe", "exec")

    def test_user_files(self):
        fs = G.user_files("bob")
        self.assertTrue(all(p.startswith("/home/bob/") for _, p, _ in fs))
        self.assertIn(("script", "/home/bob/evil/probe", "evil-bob"), fs)

    def test_feature(self):
        req = self.reqs(1)[0]
        self.assertTrue(G.request_feature(req).startswith("cmd="))


if __name__ == "__main__":
    unittest.main()
