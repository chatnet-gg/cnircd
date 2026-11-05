#!/usr/bin/env python3
"""
chatnet-audit.py -- compare a server's ircd.conf with the ChatNet standard and print only what differs.

    chatnet-audit.py <ircd.conf> <role> [--std DIR]

    role: hub          a hidden hub (no users):          chatnet-common.conf
          leaf         a server that serves users:       + chatnet-clients.conf
          leaf-webirc  a server with a web gateway:      + chatnet-webirc.conf

The standard lives in etc/chatnet-*.conf of this repository (--std defaults to ../etc next to this script). The
configuration that is checked is the file plus everything it .include's. Read-only. Exit status = number of DIFF lines.
"""
import ipaddress
import os
import re
import sys

ROLES = {
    "hub": ["chatnet-common.conf"],
    "leaf": ["chatnet-common.conf", "chatnet-clients.conf"],
    "leaf-webirc": ["chatnet-common.conf", "chatnet-clients.conf", "chatnet-webirc.conf"],
}


def strip_comments(s):
    return re.sub(r"/\*.*?\*/", "", s, flags=re.S)


def load(path, seen=None):
    """text of a conf with its .include files appended; returns (text, [included paths], [missing includes])"""
    seen = seen if seen is not None else set()
    path = os.path.realpath(path)
    if path in seen:
        return "", [], []
    seen.add(path)
    raw = strip_comments(open(path).read())
    inc, missing, extra = [], [], ""
    for m in re.finditer(r'^\s*\.include\s+"([^"]+)"', raw, re.M):
        p = m.group(1)
        if not os.path.isabs(p):
            p = os.path.join(os.path.dirname(path), p)
        if os.path.exists(p):
            t, i2, m2 = load(p, seen)
            extra += "\n" + t
            inc += [p] + i2
            missing += m2
        else:
            missing.append(p)
    return raw + extra, inc, missing


def privsets(text):
    out = {}
    for m in re.finditer(r'^\s*privset\s+"([^"]+)"\s*\{(.*?)\};', text, re.M | re.S):
        body = m.group(2).replace("privs", "", 1).replace("=", "", 1).replace(";", "")
        out[m.group(1)] = frozenset(p.strip() for p in body.split(",") if p.strip())
    return out


def modules(text):
    return set(re.findall(r'^\s*loadmodule\s+"([^"]+)"', text, re.M))


def main():
    if len(sys.argv) < 3 or sys.argv[2] not in ROLES:
        print(__doc__)
        return 2
    conf, role = sys.argv[1], sys.argv[2]
    std_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "etc")
    if "--std" in sys.argv:
        std_dir = sys.argv[sys.argv.index("--std") + 1]

    text, includes, missing_inc = load(conf)
    std_text = ""
    for f in ROLES[role]:
        std_text += "\n" + strip_comments(open(os.path.join(std_dir, f)).read())
    std_mods, std_priv = modules(std_text), privsets(std_text)
    mods, priv = modules(text), privsets(text)
    diffs = 0

    def out(tag, msg):
        nonlocal diffs
        if tag == "DIFF":
            diffs += 1
        print("[%-4s] %s" % (tag, msg))

    print("audit of %s as '%s'  (standard: %s)" % (conf, role, ", ".join(ROLES[role])))
    for p in missing_inc:
        out("DIFF", "the conf includes a file that does not exist: %s" % p)

    # modules
    miss = sorted(std_mods - mods)
    out("OK" if not miss else "DIFF", "standard modules loaded: %d of %d" % (len(std_mods) - len(miss), len(std_mods)))
    for m in miss:
        out("DIFF", "module not loaded: %s" % m)
    extra = sorted(mods - std_mods)
    for m in extra:
        out("INFO", "module loaded here and not in the standard for this role: %s" % m)

    # privsets
    for name, privs in sorted(std_priv.items()):
        if name not in priv:
            out("DIFF", "privset '%s' is not defined" % name)
        elif priv[name] != privs:
            out("DIFF", "privset '%s' differs: missing %s, extra %s" % (
                name, sorted(privs - priv[name]) or "-", sorted(priv[name] - privs) or "-"))
    ok_priv = [n for n in std_priv if n in priv and priv[n] == std_priv[n]]
    out("OK" if len(ok_priv) == len(std_priv) else "INFO", "privsets identical to the standard: %d of %d" % (len(ok_priv), len(std_priv)))
    for name in sorted(set(priv) - set(std_priv)):
        out("INFO", "privset only defined here: %s" % name)

    # network-wide blocks (service, serverhide, channel, general, alias, dnsbl) must match the standard
    def blocks(t):
        out = {}
        for m in re.finditer(r'^\s*(service|serverhide|channel|general|alias|dnsbl)(?:\s+"([^"]+)")?\s*\{', t, re.M):
            depth, j = 1, m.end()
            while j < len(t) and depth:
                depth += (t[j] == "{") - (t[j] == "}")
                j += 1
            body = re.sub(r"\s+", " ", t[m.end():j - 1]).strip()
            out.setdefault((m.group(1), m.group(2) or ""), []).append(body)
        return {k: sorted(v) for k, v in out.items()}
    sb, nb = blocks(std_text), blocks(text)
    bad_blocks = 0
    for key in sorted(sb):
        label = key[0] + (' "%s"' % key[1] if key[1] else "")
        if key not in nb:
            out("DIFF", "network block missing: %s" % label)
            bad_blocks += 1
        elif nb[key] != sb[key]:
            out("DIFF", "network block differs from the standard: %s" % label)
            bad_blocks += 1
    if not bad_blocks:
        out("OK", "network-wide blocks identical to the standard: %d" % len(sb))

    # every operator must use a defined privset
    used = set(re.findall(r'privset\s*=\s*"([^"]+)"', text))
    for name in sorted(used - set(priv)):
        out("DIFF", "an operator{} uses the privset '%s' which is not defined" % name)

    # are the standard files included, or pasted inline (inline copies drift)?
    inc_names = {os.path.basename(p) for p in includes}
    for f in ROLES[role]:
        if f not in inc_names:
            out("WARN", "%s is not .include'd: modules/privsets are written inline here and will drift" % f)

    # exempt{} for the peers (their probes and links are connections the throttle counts)
    peers = re.findall(r'connect\s+"[^"]+"\s*\{[^}]*?host\s*=\s*"([^"]+)"', text, re.S)
    have_ex = set(re.findall(r'exempt\s*\{[^}]*?ip\s*=\s*"([^"]+)"', text, re.S))
    for h in dict.fromkeys(peers):
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            out("WARN", "peer %s is a hostname: cannot tell if it has an exempt{}" % h)
            continue
        if not ip.is_loopback and h not in have_ex:
            out("DIFF", "no exempt{} for the peer %s (its probes can be throttled)" % h)

    # exception file written by cn_clone_except: must be included before every auth{}
    if "extensions/cn_clone_except" in mods:
        m_inc = re.search(r'\.include\s+"[^"]*exempt-cw\.conf"', text)
        m_auth = re.search(r"^\s*auth\s*\{", text, re.M)
        if not m_inc:
            out("DIFF", 'cn_clone_except is loaded but there is no .include "…/exempt-cw.conf"')
        elif m_auth and m_inc.start() > m_auth.start():
            out("DIFF", "the exempt-cw.conf include comes AFTER an auth{} block (it must come before: earlier = higher precedence)")
        else:
            out("OK", "exempt-cw.conf is included before the auth{} blocks")

    print("%d difference(s)" % diffs)
    return diffs


if __name__ == "__main__":
    sys.exit(main())
