# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. (MV2). Made with AI agents working in MV2's name.
"""Outcome parsing and comparison for sudo-policy-diff. Pure module, no I/O.

Direction convention: "permissive" means sudo-rs gave MORE than Todd Miller's
sudo (ran a command sudo refused, needed a weaker credential, ran as a more
privileged identity, or let a user-chosen environment value through that sudo
removed). "restrictive" is the reverse. "unclear" is a difference with no
obvious order (for example a different target uid that is not root).
"""

import json

PROBE_PREFIX = "SUDODIFF-PROBE "

STAGE_DECISION = {
    "nopass": "ALLOW_NOPASSWD",
    "pw_invoker": "ALLOW_PW_INVOKER",
    "pw_root": "ALLOW_PW_ROOT",
    "pw_target": "ALLOW_PW_TARGET",
}
RANK = {"DENY": 0, "ALLOW_PW_ROOT": 1, "ALLOW_PW_TARGET": 1,
        "ALLOW_PW_INVOKER": 2, "ALLOW_NOPASSWD": 3}

# Pre-registered as non-security even when a user-chosen value differs.
BENIGN_ENV = frozenset(("TERM", "LANG", "LANGUAGE", "COLORTERM"))
INFO_KINDS = frozenset(("ENV_BASELINE", "ENV_BENIGN", "EXEC_PATH"))
SECURITY_DIRECTIONS = frozenset(("permissive", "unclear"))


def parse_probe(stdout):
    for line in (stdout or "").splitlines():
        if line.startswith(PROBE_PREFIX):
            try:
                rec = json.loads(line[len(PROBE_PREFIX):])
            except ValueError:
                return None
            return rec if isinstance(rec, dict) else None
    return None


def short_err(stderr, limit=400):
    """stderr without the password prompt and loader noise, shortened."""
    keep = []
    for ln in (stderr or "").splitlines():
        s = ln.strip()
        if not s or "password for" in s or s.startswith("Password:"):
            continue
        keep.append(s)
    return " | ".join(keep)[:limit]


def decide(attempts):
    """First attempt that ran the probe decides; none -> DENY."""
    for a in attempts:
        if a.get("probe") is not None:
            return STAGE_DECISION.get(a.get("stage"), "ALLOW_UNKNOWN"), a["probe"]
    return "DENY", None


def finding(kind, direction, detail):
    return {"kind": kind, "direction": direction, "detail": detail}


def key(f):
    return (f["kind"], f["direction"], f["detail"])


def is_security(f):
    return f["direction"] in SECURITY_DIRECTIONS and f["kind"] not in INFO_KINDS


def _set_direction(rs_set, ws_set):
    if rs_set == ws_set:
        return None
    if rs_set > ws_set:
        return "permissive"
    if rs_set < ws_set:
        return "restrictive"
    return "unclear"


def compare(ws_dec, ws_probe, rs_dec, rs_probe, user_env):
    """Findings for one request. ws = Todd Miller's sudo, rs = sudo-rs."""
    out = []
    if ws_dec != rs_dec:
        rw, rr = RANK.get(ws_dec, 0), RANK.get(rs_dec, 0)
        if rr > rw:
            d = "permissive"
        elif rr < rw:
            d = "restrictive"
        else:
            d = "unclear"
        kind = "DECISION" if (rw == 0 or rr == 0) else "AUTH"
        out.append(finding(kind, d, "ws=%s rs=%s" % (ws_dec, rs_dec)))
    if ws_probe is None or rs_probe is None:
        return out
    for f in ("uid", "euid", "gid", "egid"):
        w, r = ws_probe.get(f), rs_probe.get(f)
        if w != r:
            d = "permissive" if r == 0 else ("restrictive" if w == 0 else "unclear")
            out.append(finding("IDENTITY", d, "%s ws=%s rs=%s" % (f, w, r)))
    wg = set(ws_probe.get("groups") or ())
    rg = set(rs_probe.get("groups") or ())
    dg = _set_direction(rg, wg)
    if dg:
        out.append(finding("GROUPS", dg, "ws-only=%s rs-only=%s" % (
            sorted(wg - rg), sorted(rg - wg))))
    if ws_probe.get("tag") != rs_probe.get("tag"):
        out.append(finding("EXEC", "unclear", "ws=%s rs=%s" % (
            ws_probe.get("tag"), rs_probe.get("tag"))))
    elif ws_probe.get("exe") != rs_probe.get("exe"):
        out.append(finding("EXEC_PATH", "info", "ws=%s rs=%s" % (
            ws_probe.get("exe"), rs_probe.get("exe"))))
    if ws_probe.get("argv") != rs_probe.get("argv"):
        out.append(finding("ARGV", "unclear", "ws=%s rs=%s" % (
            ws_probe.get("argv"), rs_probe.get("argv"))))
    if ws_probe.get("cwd") != rs_probe.get("cwd"):
        out.append(finding("CWD", "unclear", "ws=%s rs=%s" % (
            ws_probe.get("cwd"), rs_probe.get("cwd"))))
    wu, ru = ws_probe.get("umask"), rs_probe.get("umask")
    if wu != ru and isinstance(wu, int) and isinstance(ru, int):
        if (ru | wu) == wu:
            d = "permissive"   # sudo-rs masks fewer permission bits
        elif (ru | wu) == ru:
            d = "restrictive"
        else:
            d = "unclear"
        out.append(finding("UMASK", d, "ws=%04o rs=%04o" % (wu, ru)))
    we = ws_probe.get("env") or {}
    re_ = rs_probe.get("env") or {}
    for name in sorted(user_env):
        val = user_env[name]
        rs_has = re_.get(name) == val
        ws_has = we.get(name) == val
        if rs_has != ws_has:
            d = "permissive" if rs_has else "restrictive"
            kind = "ENV_BENIGN" if name in BENIGN_ENV else "ENV"
            out.append(finding(kind, d, name))
    only = sorted((set(we) ^ set(re_)) - set(user_env))
    if only:
        out.append(finding("ENV_BASELINE", "info", " ".join(only)))
    return out


def tally(findings_iter):
    counts = {}
    for f in findings_iter:
        k = "%s/%s" % (f["kind"], f["direction"])
        counts[k] = counts.get(k, 0) + 1
    return dict(sorted(counts.items()))


def grade(summary):
    """Raw, automatic grading of PREREG predictions P1-P7 from summary counts.
    Hand triage (PREREG section 6) decides what any permissive finding means."""
    fc = summary.get("finding_counts", {})

    def any_of(prefixes, directions):
        return sum(v for k, v in fc.items()
                   if k.split("/")[0] in prefixes and k.split("/")[1] in directions)

    ctrl = summary.get("control", {})
    vis = summary.get("visudo", {})
    total_pol = sum(vis.values()) or 1
    ws_ok_rs_bad = vis.get("ws_ok/rs_bad", 0)
    return {
        "P1_control_clean": ctrl.get("requests", 0) > 0 and ctrl.get("noisy", 0) == 0,
        "P2_preflight_ok": bool(summary.get("preflight_ok")),
        "P3_any_decision_divergence": any_of(("DECISION", "AUTH"),
                                             ("permissive", "restrictive", "unclear")) > 0,
        "P4_permissive_decision_or_auth": any_of(("DECISION", "AUTH"), ("permissive",)) > 0,
        "P5_permissive_env": any_of(("ENV",), ("permissive",)) > 0,
        "P6_identity_or_groups": any_of(("IDENTITY", "GROUPS"),
                                        ("permissive", "restrictive", "unclear")) > 0,
        "P7_rs_rejects_5pct": ws_ok_rs_bad / float(total_pol) >= 0.05,
    }
