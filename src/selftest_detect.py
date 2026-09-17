#!/usr/bin/env python3
"""POSITIVE CONTROL: inject a real change into a real build and prove it is caught.

The offline corpus returns "unchanged" for all five packages, correctly -- those
are trivial hook packages and nothing about their behaviour changed. But five
greens say NOTHING about whether the differ can detect anything at all. A suite
that has never been red is not evidence.

So this takes a real AUR package that builds offline, builds its actual PKGBUILD
as the baseline, then builds a copy with one anomalous line added, and asserts
the difference is found. The baseline is genuine -- 400 greps of makepkg
machinery and all -- so this also proves the injected signal survives being
diffed against real noise.
"""
import os, sys, shutil, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aur
from runner import build, summarise
from profile import compare

PKG = "update-grub"          # source=() is local files, so it builds with no network

INJECT = '''
build() {
  # --- injected by selftest_detect.py: the behaviour a hijack would add ---
  /usr/bin/getent hosts example.com >/dev/null 2>&1 || true
  : > /usr/lib/selftest-should-be-refused 2>/dev/null || true
  /usr/bin/env true
}
'''


def main():
    tmp = tempfile.mkdtemp(prefix="abd-detect-")
    try:
        repo = aur.clone(PKG, tmp)
        vs = aur.versions(repo, limit=2)
        sha = vs[0][0]

        base_dir = aur.checkout_to(repo, sha, os.path.join(tmp, "baseline"))
        hij_dir = aur.checkout_to(repo, sha, os.path.join(tmp, "injected"))
        pb = os.path.join(hij_dir, "PKGBUILD")
        with open(pb, "a") as fh:
            fh.write(INJECT)

        print("package %s @ %s" % (PKG, sha[:10]))
        print("baseline = the real PKGBUILD; injected = the same plus one build() block\n")

        profs = {}
        for label, d in (("baseline", base_dir), ("injected", hij_dir)):
            p, meta = build(d, timeout=300)
            profs[label] = p
            print("  %-9s rc=%-4s %s" % (label, meta["rc"], summarise(p)))

        assert profs["baseline"]["_build"]["usable"], "baseline did not build; cannot control"
        assert profs["injected"]["_build"]["usable"], "injected build failed; test is invalid"

        v, why, d = compare(profs["baseline"], profs["injected"])
        print("\n  VERDICT: %s" % v)
        for w in why:
            print("    - %s" % w)

        assert v == "changed", "POSITIVE CONTROL FAILED: injected behaviour was not detected"
        assert d.get("execs"), "expected the injected exec to surface"

        # and the reverse direction must stay silent: real vs itself
        v2, why2, _ = compare(profs["baseline"], profs["baseline"])
        assert v2 == "unchanged", "a build compared with itself must not alarm"
        print("\n  control (real build vs itself): %s" % v2)
        print("\nself-test: injected change DETECTED, self-comparison silent")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
