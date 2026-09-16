#!/usr/bin/env python3
"""Fetch a package's own history from the AUR, to diff a version against itself.

Every AUR package is a git repository at aur.archlinux.org/<name>.git whose
commits are the successive PKGBUILDs. That history is the baseline: the useful
signal is not "this build touched the network" -- cargo and npm do that
legitimately -- but "this package has not contacted this host in its last six
releases and now it does".

THE LIMIT, stated because it is real and not incidental: a historical PKGBUILD
may no longer build. Upstream tarballs move, mirrors expire, toolchains drift.
When the last-known-good version does not reproduce there is NO baseline, and
the honest output is "no comparison available" plus the static source=()
allowlist -- not a verdict derived from a build that failed for unrelated
reasons.
"""
import os, re, shutil, subprocess, tempfile

AUR_GIT = "https://aur.archlinux.org/%s.git"


def _git(args, cwd=None, timeout=120):
    p = subprocess.run(["git"] + args, cwd=cwd, capture_output=True,
                       text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args[:2]), p.stderr[-300:]))
    return p.stdout


def exists(pkg):
    try:
        out = _git(["ls-remote", AUR_GIT % pkg], timeout=40)
        return bool(out.strip())
    except (RuntimeError, subprocess.SubprocessError):
        return False


def clone(pkg, dest=None):
    dest = dest or tempfile.mkdtemp(prefix="aur-%s-" % pkg)
    target = os.path.join(dest, pkg)
    _git(["clone", "--quiet", AUR_GIT % pkg, target], timeout=180)
    return target


def versions(repo, limit=12):
    """Commits that changed the PKGBUILD, newest first: (sha, date, pkgver)."""
    log = _git(["log", "--format=%H|%ad", "--date=short", "-n", str(limit),
                "--", "PKGBUILD"], cwd=repo)
    out = []
    for line in log.strip().splitlines():
        sha, date = line.split("|", 1)
        try:
            body = _git(["show", "%s:PKGBUILD" % sha], cwd=repo)
        except RuntimeError:
            continue
        # strip surrounding quotes: pkgbuild-introspection renders pkgver='9',
        # and the raw capture produced versions like '9'-'1'
        def _val(pat):
            mm = re.search(pat, body, re.M)
            return mm.group(1).strip("'\"") if mm else "?"
        ver = _val(r"^pkgver\s*=\s*(\S+)") + "-" + _val(r"^pkgrel\s*=\s*(\S+)")
        out.append((sha, date, ver))
    return out


def checkout_to(repo, sha, dest):
    """Materialise one historical version into its own directory."""
    os.makedirs(dest, exist_ok=True)
    tar = _git(["archive", sha], cwd=repo)
    p = subprocess.run(["tar", "-x", "-C", dest], input=tar.encode("utf-8", "surrogateescape"),
                       capture_output=True)
    if p.returncode != 0:
        # binary-safe path for repos with non-UTF8 blobs
        raw = subprocess.run(["git", "archive", sha], cwd=repo, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", dest], input=raw, capture_output=True, check=True)
    return dest
