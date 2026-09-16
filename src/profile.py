#!/usr/bin/env python3
"""Turn a build's syscall trace into a behaviour profile, and diff two of them.

The sandbox is plumbing. THE BASELINE IS THE HARD PART. Legitimate builds
already fetch from the network (cargo, npm, go), write all over the place, and
exec compilers -- so "this build touched the network" is a false-positive
firehose, not a detection.

The signal that survives that is a CHANGE against the same package's own
history: this PKGBUILD has not contacted registry.npmjs.org in its last six
releases and now it does. That is what this module computes.
"""
import re, json, os
from collections import Counter


class NoBaseline(Exception):
    """Raised when the older build produced no usable profile to compare against."""

# A build tree is allowed to be written to; that is what a build is.
BUILD_PREFIXES = ("/build", "/tmp", "/dev", "/proc", "/sys", "/run")

# Match the quoted address specifically. A lazy [^)]*? before the capture will
# happily consume into `inet_addr(` and capture a single letter out of it --
# which is exactly what it did, yielding endpoints like "e:443" that compared
# equal between builds and silently suppressed the diff.
_CONNECT = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((\d+)\).*?"([0-9a-fA-F:.]+)"')
_EXECVE = re.compile(r'execve\("([^"]+)"')
_OPENW = re.compile(r'open(?:at)?\((?:AT_FDCWD|\d+),\s*"([^"]+)",\s*([^,)]+)')
_GETADDR = re.compile(r'(?:sendto|write)\(\d+,\s*".*?([a-z0-9][a-z0-9.-]{3,}\.[a-z]{2,})')


def parse_strace(text):
    """Extract a behaviour profile from `strace -f` output.

    strace is the v1 capture layer because it needs no privileges and no kernel
    modules. It is also a 20-50x slowdown on a real compile, which is fine for a
    one-off audit and wrong for "run this before every install" -- a pcap on the
    sandbox veth plus auditd exec events is the faster v2 and is noted as such
    rather than pretended away.
    """
    prof = {"connects": Counter(), "execs": Counter(), "writes_outside": Counter(),
            "names": Counter()}
    for line in text.splitlines():
        m = _CONNECT.search(line)
        if m:
            port, addr = m.group(1), m.group(2)
            if addr not in ("", "0.0.0.0"):
                prof["connects"]["%s:%s" % (addr, port)] += 1
        m = _EXECVE.search(line)
        if m:
            prof["execs"][m.group(1)] += 1
        m = _OPENW.search(line)
        if m:
            path, flags = m.group(1), m.group(2)
            if ("O_WRONLY" in flags or "O_RDWR" in flags or "O_CREAT" in flags) \
               and not path.startswith(BUILD_PREFIXES):
                prof["writes_outside"][path] += 1
        m = _GETADDR.search(line)
        if m:
            prof["names"][m.group(1)] += 1
    return {k: dict(v) for k, v in prof.items()}


def looks_unbuilt(prof):
    """A profile from a build that did not really run.

    Every real makepkg invocation execs something -- at minimum bash and the
    packaging helpers. A profile with no execs did not observe a build, whether
    because it failed, timed out, or the trace was never written.
    """
    return not prof.get("execs")


def diff(old, new):
    """What the new version does that the old one never did.

    Deliberately one-directional: a build that STOPPED contacting a host is not
    interesting, a build that started is.

    REFUSES AN UNUSABLE BASELINE rather than diffing against it. If the older
    build failed, its profile is empty, and an empty baseline makes EVERY
    behaviour of the new version look newly introduced -- including /usr/bin/gcc.
    "New version fetches during build, old version's build FAILED" and "new
    version fetches, old version did not" produce an identical diff and mean
    completely different things. Raising here means the distinction cannot be
    lost by a caller who forgot to check, which a separate guard in the CLI
    could not guarantee. (rafiulbari's alienware-main-chat, 2026-09-16.)
    """
    if looks_unbuilt(old):
        raise NoBaseline("the baseline profile records no execs, so the baseline "
                         "build did not run; there is nothing to compare against")
    out = {}
    for key in ("connects", "execs", "writes_outside", "names"):
        o, n = set(old.get(key, {})), set(new.get(key, {}))
        added = sorted(n - o)
        if added:
            out[key] = added
    return out


def compare(old, new, has_history=True):
    """diff + verdict in one call, carrying baseline provenance honestly."""
    if not has_history:
        return "unknown", ["no prior version to diff against; static allowlist only"], {}
    try:
        d = diff(old, new)
    except NoBaseline as e:
        return "unknown", ["%s" % e], {}
    v, why = verdict(d, has_history=True)
    return v, why, d


def verdict(d, has_history=True):
    """A judgement with its reasoning attached, not a score.

    With no history there is nothing to diff against, and saying so is more
    useful than flagging every first-seen package -- which is every AUR package
    the first time anyone runs this.
    """
    if not has_history:
        return "unknown", ["no prior version to diff against; static allowlist only"]
    why = []
    if d.get("names"):
        why.append("resolved names not seen in the previous build: %s" % ", ".join(d["names"][:5]))
    if d.get("connects"):
        why.append("new outbound endpoints: %s" % ", ".join(d["connects"][:5]))
    if d.get("writes_outside"):
        why.append("wrote outside the build tree: %s" % ", ".join(d["writes_outside"][:5]))
    if d.get("execs"):
        why.append("executed binaries absent from the previous build: %s" % ", ".join(d["execs"][:5]))
    return ("changed" if why else "unchanged"), (why or ["no behavioural change"])


if __name__ == "__main__":
    # Self-test with synthetic traces, so it runs without strace installed.
    clean = '''
execve("/usr/bin/makepkg", ["makepkg"], 0x0) = 0
execve("/usr/bin/gcc", ["gcc","-c","main.c"], 0x0) = 0
openat(AT_FDCWD, "/build/src/main.o", O_WRONLY|O_CREAT, 0644) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.121.3")}, 16) = 0
'''
    hijacked = clean + '''
sendto(5, "\\3www\\7example\\3com\\0", 25, 0, NULL, 0) = 25
connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.16.23.35")}, 16) = 0
execve("/tmp/.cache/update", ["update"], 0x0) = 0
openat(AT_FDCWD, "/home/u/.config/systemd/user/upd.service", O_WRONLY|O_CREAT, 0644) = 8
'''
    a, b = parse_strace(clean), parse_strace(hijacked)
    v, why, d = compare(a, b)
    print("baseline build:", json.dumps(a, indent=None)[:120])
    print("\nverdict: %s" % v)
    for w in why:
        print("  - %s" % w)
    assert v == "changed" and "connects" in d and "execs" in d, "differ failed"
    v2, _why2, _d2 = compare(a, a)
    assert v2 == "unchanged", "clean-vs-clean must not alarm"

    # a failed baseline must NOT render as "the new version introduced everything"
    empty = {"connects": {}, "execs": {}, "writes_outside": {}, "names": {}}
    v3, why3, _ = compare(empty, b)
    assert v3 == "unknown", "an unbuilt baseline must be unknown, not changed"
    print("\nself-test: changed-detects=OK  clean-vs-clean-silent=OK")
    print("           failed-baseline -> %s (%s)" % (v3, why3[0][:60]))
