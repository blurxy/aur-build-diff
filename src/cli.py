#!/usr/bin/env python3
"""aur-build-diff -- did this package's build behaviour change?

Fetches a package's own git history, builds two versions in an isolated sandbox,
and reports what the newer one does that the older one never did.

BUILDING IS OPT-IN. `makepkg` executes arbitrary code from a PKGBUILD, and the
whole point of this tool is that you do not yet know whether that code is
hostile. The sandbox is real -- no routes, no resolver socket, verified by
`--check-sandbox` -- but a sandbox is a mitigation, not a permission slip. So
the default is a plan showing exactly what WOULD be built, and nothing runs
until you pass --build.
"""
import argparse, os, shutil, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aur, sandbox
from profile import diff, verdict
from runner import build as run_build, summarise


def cmd_check_sandbox(_a):
    ok, detail = sandbox.verify()
    for k, v in (detail.items() if isinstance(detail, dict) else []):
        print("  %-30s %s" % (k, v))
    print("\nhardened sandbox isolated:", ok)
    if not ok:
        print("REFUSING to build: the sandbox does not hold on this machine.", file=sys.stderr)
    return 0 if ok else 1


def cmd_history(a):
    if not aur.exists(a.package):
        print("no such AUR package: %s" % a.package, file=sys.stderr)
        return 2
    tmp = tempfile.mkdtemp(prefix="abd-hist-")
    try:
        repo = aur.clone(a.package, tmp)
        vs = aur.versions(repo, limit=a.limit)
        print("%-12s %-12s %s" % ("commit", "date", "version"))
        for sha, date, ver in vs:
            print("%-12s %-12s %s" % (sha[:10], date, ver))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


def cmd_diff(a):
    ok, _ = sandbox.verify()
    if not ok:
        print("REFUSING: sandbox isolation check failed. Run --check-sandbox.", file=sys.stderr)
        return 1
    if not aur.exists(a.package):
        print("no such AUR package: %s" % a.package, file=sys.stderr)
        return 2

    tmp = tempfile.mkdtemp(prefix="abd-")
    try:
        repo = aur.clone(a.package, tmp)
        vs = aur.versions(repo, limit=a.limit)
        if len(vs) < 2:
            print("only %d PKGBUILD revision(s); nothing to diff against." % len(vs))
            print("VERDICT: unknown -- no prior version. Static source=() review only.")
            return 0
        new, old = vs[0], vs[a.against]

        print("package   %s" % a.package)
        print("newer     %s  %s  %s" % (new[0][:10], new[1], new[2]))
        print("baseline  %s  %s  %s" % (old[0][:10], old[1], old[2]))
        if not a.do_build:
            print("\nPLAN ONLY. Nothing has been built.")
            print("Re-run with --build to execute both PKGBUILDs in the sandbox.")
            print("This runs third-party build scripts; the sandbox has no route out")
            print("and no resolver socket, verified before each run.")
            return 0

        profs = {}
        for label, (sha, _d, ver) in (("baseline", old), ("newer", new)):
            d = aur.checkout_to(repo, sha, os.path.join(tmp, label))
            print("\nbuilding %s (%s)..." % (label, ver))
            p, meta = run_build(d, timeout=a.timeout)
            profs[label] = p
            note = "timed out" if meta["timeout"] else "rc=%s" % meta["rc"]
            print("  %s  trace=%d B  %s" % (note, meta["trace_bytes"], summarise(p)))
            if meta["timeout"] or (meta["rc"] not in (0, None)):
                print("  NOTE: this build did not succeed. A failed baseline means")
                print("  there is NO comparison -- an old PKGBUILD may simply not")
                print("  reproduce today (moved sources, drifted toolchain).")
                if label == "baseline":
                    print("\nVERDICT: unknown -- baseline did not build.")
                    return 0

        d = diff(profs["baseline"], profs["newer"])
        v, why = verdict(d, has_history=True)
        print("\nVERDICT: %s" % v)
        for w in why:
            print("  - %s" % w)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(prog="aur-build-diff", description=__doc__.splitlines()[0])
    ap.add_argument("package", nargs="?")
    ap.add_argument("--history", action="store_true", help="list PKGBUILD revisions and exit")
    ap.add_argument("--build", dest="do_build", action="store_true",
                    help="actually build both versions (runs third-party code in the sandbox)")
    ap.add_argument("--against", type=int, default=1, metavar="N",
                    help="compare against the Nth older revision (default 1)")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--check-sandbox", action="store_true",
                    help="prove isolation holds here, with the permissive profile as a control")
    a = ap.parse_args()

    if a.check_sandbox:
        return cmd_check_sandbox(a)
    if not a.package:
        ap.print_help()
        return 0
    if a.history:
        return cmd_history(a)
    return cmd_diff(a)


if __name__ == "__main__":
    sys.exit(main())
