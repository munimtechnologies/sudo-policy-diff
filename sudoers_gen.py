# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""Random sudoers policies and sudo requests for sudo-policy-diff.

Pure module: no I/O, deterministic for a given random.Random. Everything it
emits stays inside the sudoers subset that BOTH Todd Miller's sudo and sudo-rs
document (see PREREG.md section 3). In particular it never emits wildcards in
command arguments other than a final "*", and never NOEXEC, INTERCEPT,
sudoedit, digests, env_delete, regular expressions or LDAP.
"""

import random

HOST_TOKEN = "{HOST}"
HEADER = (
    "# sudo-policy-diff generated policy",
    "Defaults timestamp_timeout=0",
)

GROUPS = (("team", 3001), ("wheel", 3002), ("ops", 3003), ("svcgrp", 3500))
# name, uid, primary gid, supplementary group names
USERS = (
    ("alice", 2001, 2001, ("team", "wheel")),
    ("bob", 2002, 2002, ("team",)),
    ("carol", 2003, 2003, ()),
    ("svc", 2500, 3500, ()),
)
INVOKERS = ("alice", "bob", "carol")
UID_NAMES = {0: "root", 2001: "alice", 2002: "bob", 2003: "carol", 2500: "svc"}

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PROBE_PREFIX = "SUDODIFF-PROBE "

# Root-owned probe programs (path, tag).
PROBES = (
    ("/usr/local/bin/probe", "probe"),
    ("/usr/local/bin/probe2", "probe2"),
    ("/usr/local/sbin/probe3", "probe3"),
    ("/opt/tools/probe4", "probe4"),
    ("/opt/tools/sub/probe5", "probe5"),
)


def user_files(user):
    """Files the invoking user owns: (kind, path, symlink target or tag)."""
    h = "/home/" + user
    return (
        ("symlink", h + "/bin/probe", "/usr/local/bin/probe"),
        ("symlink", h + "/bin/zz", "/usr/local/bin/probe"),
        ("symlink", h + "/bin/probe4", "/opt/tools/probe4"),
        ("script", h + "/evil/probe", "evil-" + user),
        ("script", h + "/evil/probe4", "evil-" + user),
    )


def probe_script(tag):
    """A probe program: prints one line with who/what/where it ran as."""
    return (
        "#!/usr/bin/python3 -I\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "import json, os, sys\n"
        "m = os.umask(0)\n"
        "os.umask(m)\n"
        "try:\n"
        "    cwd = os.getcwd()\n"
        "except OSError as e:\n"
        "    cwd = 'ERR:' + str(e.errno)\n"
        "rec = {'tag': %r, 'exe': sys.argv[0], 'argv': sys.argv[1:],\n"
        "       'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),\n"
        "       'egid': os.getegid(), 'groups': sorted(os.getgroups()),\n"
        "       'cwd': cwd, 'umask': m, 'env': dict(os.environ)}\n"
        "sys.stdout.write(%r + json.dumps(rec, sort_keys=True) + '\\n')\n"
    ) % (tag, PROBE_PREFIX)


# ---------------------------------------------------------------- policies

U_ITEMS = ("alice", "bob", "carol", "%team", "%wheel", "%ops", "#2001", "#2002",
           "%#3001", "%#3002", "ALL")
H_ITEMS = ("ALL", "ALL", "ALL", "ALL", "ALL", "ALL", HOST_TOKEN, "otherhost")
RU_ITEMS = ("root", "bob", "carol", "svc", "#2500", "#4242", "#0", "ALL",
            "%team", "%svcgrp", "%#3500")
RG_ITEMS = ("svcgrp", "team", "ops", "wheel", "#3500", "ALL")
CMD_PATHS = (
    "/usr/local/bin/probe", "/usr/local/bin/probe", "/usr/local/bin/probe2",
    "/usr/local/sbin/probe3", "/opt/tools/probe4", "/opt/tools/sub/probe5",
    "/usr/local/bin/probe*", "/usr/local/*/probe?", "/opt/tools/*",
    "/opt/tools/sub/*", "/usr/local/bin/pro[b]e", "/opt/tools/probe[0-9]",
)
DIR_PATHS = ("/usr/local/bin/", "/opt/tools/", "/opt/tools/sub/")
# None = no argument spec (any arguments). Only a FINAL "*" is a wildcard.
ARG_SPECS = (None, None, None, '""', "a", "a b", "-v", "a *", "*")
TAG_SETS = ((), (), ("NOPASSWD",), ("NOPASSWD",), ("PASSWD",),
            ("NOPASSWD", "SETENV"), ("SETENV",), ("NOSETENV",),
            ("NOPASSWD", "NOSETENV"), ("EXEC",))
CWD_SPECS = (None,) * 8 + ("CWD=*", "CWD=/opt/tools", "CWD=~")
DEFAULT_PARAMS = (
    'env_keep += "FOO"', 'env_keep += "BAR*"', 'env_keep += "HOME"',
    'env_keep += "LD_PRELOAD"', 'env_keep = "FOO QUY"', 'env_keep -= "DISPLAY"',
    'env_check += "QUX QUY"', 'env_check += "TZ"', 'setenv', '!setenv',
    'secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
    'secure_path="/opt/tools:/usr/bin:/bin"', 'rootpw', 'targetpw', '!rootpw',
    'umask=0077', 'umask=0000', 'umask_override', 'runcwd=/opt/tools', 'runcwd=*',
)
DEFAULT_SCOPES = ("", "", "", "", "", "", ":alice", ":%team", ":#2002", ">root",
                  ">bob", "!/usr/local/bin/probe2", "@" + HOST_TOKEN, "@otherhost")


def _items(rng, pool, aliases, alias_name, max_n, neg_p):
    n = 1 if rng.random() < 0.7 else rng.randint(2, max_n)
    pool2 = list(pool)
    if alias_name and alias_name in aliases:
        pool2.append(alias_name)
    out = []
    for _ in range(n):
        it = rng.choice(pool2)
        p = neg_p if n > 1 else neg_p * 0.15
        if rng.random() < p:
            it = "!" + it
        out.append(it)
    return out


def _cmnd(rng, aliases, allow_alias=True, neg_p=0.15):
    r = rng.random()
    if allow_alias and "CA" in aliases and r < 0.15:
        base = "CA"
    elif r < 0.25:
        base = "ALL"
    elif r < 0.40:
        base = rng.choice(DIR_PATHS)
    else:
        base = rng.choice(CMD_PATHS)
        a = rng.choice(ARG_SPECS)
        if a is not None:
            base = base + " " + a
    if rng.random() < neg_p:
        base = "!" + base
    return base


def _runas(rng, aliases):
    r = rng.random()
    users = ",".join(_items(rng, RU_ITEMS, aliases, "RA", 3, 0.15))
    if r < 0.55:
        return "(" + users + ")"
    groups = ",".join(_items(rng, RG_ITEMS, (), "", 2, 0.1))
    if r < 0.80:
        return "(" + users + ":" + groups + ")"
    if r < 0.95:
        return "(:" + groups + ")"
    return "()"


def _cmnd_spec(rng, aliases, first):
    parts = []
    if rng.random() < (0.55 if first else 0.25):
        parts.append(_runas(rng, aliases))
    cwd = rng.choice(CWD_SPECS)
    if cwd:
        parts.append(cwd)
    for t in rng.choice(TAG_SETS):
        parts.append(t + ":")
    parts.append(_cmnd(rng, aliases))
    return " ".join(parts)


def _aliases(rng):
    lines, names = [], set()
    if rng.random() < 0.25:
        lines.append("User_Alias UA = " + ", ".join(_items(rng, U_ITEMS, (), "", 3, 0.25)))
        names.add("UA")
    if rng.random() < 0.25:
        lines.append("Runas_Alias RA = " + ", ".join(_items(rng, RU_ITEMS, (), "", 3, 0.2)))
        names.add("RA")
    if rng.random() < 0.15:
        lines.append("Host_Alias HA = " + ", ".join(
            _items(rng, ("ALL", HOST_TOKEN, "otherhost"), (), "", 2, 0.2)))
        names.add("HA")
    if rng.random() < 0.35:
        n = rng.randint(1, 3)
        lines.append("Cmnd_Alias CA = " + ", ".join(
            _cmnd(rng, (), allow_alias=False) for _ in range(n)))
        names.add("CA")
    return lines, names


def _defaults(rng, aliases):
    scopes = list(DEFAULT_SCOPES)
    if "UA" in aliases:
        scopes.append(":UA")
    if "CA" in aliases:
        scopes.append("!CA")
    out = []
    for _ in range(rng.choice((0, 0, 1, 1, 2, 3))):
        out.append("Defaults%s %s" % (rng.choice(scopes), rng.choice(DEFAULT_PARAMS)))
    return out


def _user_spec(rng, aliases):
    users = ", ".join(_items(rng, U_ITEMS, aliases, "UA", 2, 0.25))
    hosts = ", ".join(_items(rng, H_ITEMS, aliases, "HA", 2, 0.2))
    n = rng.choice((1, 1, 1, 2, 2, 3))
    specs = [_cmnd_spec(rng, aliases, i == 0) for i in range(n)]
    return "%s %s = %s" % (users, hosts, ", ".join(specs))


def generate_policy(rng):
    """Body lines of one random policy (the HEADER is added by render_policy)."""
    lines, names = _aliases(rng)
    lines += _defaults(rng, names)
    for _ in range(rng.choice((1, 2, 2, 3, 4))):
        lines.append(_user_spec(rng, names))
    return lines


def policy_template(lines):
    return "\n".join(list(HEADER) + list(lines)) + "\n"


def render_policy(lines, hostname):
    return policy_template(lines).replace(HOST_TOKEN, hostname)


# ---------------------------------------------------------------- requests

# (command as typed, working directory of the invoking process)
CMD_FORMS = (
    ("/usr/local/bin/probe", "/"), ("/usr/local/bin/probe", "/"),
    ("/usr/local/bin/probe2", "/"), ("/usr/local/sbin/probe3", "/"),
    ("/opt/tools/probe4", "/"), ("/opt/tools/sub/probe5", "/"),
    ("/usr/local/bin/../bin/probe", "/"), ("/usr/local/bin//probe", "/"),
    ("/opt/tools/sub/../probe4", "/"),
    ("{home}/bin/probe", "/"), ("{home}/bin/zz", "/"), ("{home}/bin/probe4", "/"),
    ("{home}/evil/probe", "/"), ("{home}/evil/probe4", "/"),
    ("probe", "/"), ("probe4", "/"),
    ("./probe", "/usr/local/bin"), ("./probe4", "/opt/tools"),
    ("sub/probe5", "/opt/tools"), ("../bin/probe", "/usr/local/sbin"),
)
ARGS_CHOICES = ((), (), (), ("",), ("a",), ("a", "b"), ("-v",), ("a", "b", "c"),
                ("*",), ("a", "*"))
RUNAS_U = (None, None, None, None, "root", "root", "bob", "svc", "#2500", "#4242",
           "#0", "carol", "alice")
RUNAS_G = (None,) * 7 + ("svcgrp", "team", "ops", "#3500", "#3003", "wheel")
ENV_CHOICES = (
    ("FOO", "user-foo"), ("BARX", "user-barx"), ("QUX", "/tmp/user-qux"),
    ("QUY", "safe-quy"), ("TZ", "/tmp/user-tz"), ("LD_PRELOAD", "/tmp/user-ld.so"),
    ("LD_LIBRARY_PATH", "/tmp/user-lib"), ("PYTHONPATH", "/tmp/user-py"),
    ("BASH_ENV", "/tmp/user-bashenv"), ("HOME", "/tmp/user-home"),
    ("SHELL", "/tmp/user-shell"), ("PS4", "$(id)"), ("SUDO_USER", "forged"),
    ("DISPLAY", ":7"), ("FNV", "() { :; }; echo pwned"),
    ("PATH", "{home}/evil:/usr/local/bin:/usr/bin:/bin"),
    ("PATH", "{home}/bin:/opt/tools:/usr/bin:/bin"), ("PATH", ".:/usr/bin:/bin"),
)
CL_ENV = ("FOO=cl-foo", "LD_PRELOAD=/tmp/cl-ld.so", "PATH={home}/evil:/usr/bin:/bin",
          "HOME=/tmp/cl-home", "QUY=cl-quy", "SUDO_USER=cl-forged", "BARX=cl-barx")
CHDIRS = ("/opt/tools", "/tmp", "/root")


def generate_request(rng):
    inv = rng.choice(INVOKERS)
    cmd, cwd = rng.choice(CMD_FORMS)
    env = {}
    for _ in range(rng.choice((0, 0, 1, 2, 3))):
        k, v = rng.choice(ENV_CHOICES)
        env[k] = v
    cl = []
    if rng.random() < 0.25:
        cl = list(rng.sample(CL_ENV, rng.randint(1, 2)))
    return {
        "invoker": inv,
        "runas_user": rng.choice(RUNAS_U),
        "runas_group": rng.choice(RUNAS_G),
        "cmd": cmd,
        "args": list(rng.choice(ARGS_CHOICES)),
        "cwd": cwd,
        "env": env,
        "cmdline_env": cl,
        "preserve_env": rng.random() < 0.15,
        "chdir": rng.choice(CHDIRS) if rng.random() < 0.12 else None,
    }


def expand(s, invoker):
    return s.replace("{home}", "/home/" + invoker)


def base_env(invoker):
    return {"PATH": DEFAULT_PATH, "HOME": "/home/" + invoker, "USER": invoker,
            "LOGNAME": invoker, "SHELL": "/bin/sh", "LANG": "C.UTF-8", "TERM": "dumb"}


def invoker_env(req):
    """Environment the invoking user's sudo process starts with."""
    inv = req["invoker"]
    env = base_env(inv)
    for k, v in req.get("env", {}).items():
        env[k] = expand(v, inv)
    return env


def user_env(req):
    """Every variable the invoking user controls -> the value they chose."""
    env = invoker_env(req)
    for item in req.get("cmdline_env", []):
        k, _, v = item.partition("=")
        env[k] = expand(v, req["invoker"])
    return env


def sudo_argv(binary, req, mode):
    """argv for one sudo invocation; mode is "-n" or "-S"."""
    inv = req["invoker"]
    a = [binary, mode]
    if req.get("runas_user"):
        a += ["-u", req["runas_user"]]
    if req.get("runas_group"):
        a += ["-g", req["runas_group"]]
    if req.get("preserve_env"):
        a.append("-E")
    if req.get("chdir"):
        a += ["-D", req["chdir"]]
    a += [expand(x, inv) for x in req.get("cmdline_env", [])]
    a.append(expand(req["cmd"], inv))
    a += list(req.get("args", []))
    return a


def target_user(req):
    """Name of the user the command should run as (None if unknown uid)."""
    ru = req.get("runas_user")
    if ru is None:
        return req["invoker"] if req.get("runas_group") else "root"
    if ru.startswith("#"):
        try:
            return UID_NAMES.get(int(ru[1:]))
        except ValueError:
            return None
    return ru


def request_feature(req):
    """Coarse shape of a request, used to de-duplicate findings."""
    return "cmd=%s ru=%d rg=%d E=%d D=%d cl=%d" % (
        req["cmd"], req.get("runas_user") is not None,
        req.get("runas_group") is not None, bool(req.get("preserve_env")),
        req.get("chdir") is not None, bool(req.get("cmdline_env")))
