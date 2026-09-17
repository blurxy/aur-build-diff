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
import aur, sandbox, sources
from profile import compare, looks_unbuilt
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
    # The sandbox only gates BUILDING. The declaration diff reads text and runs
    # no third-party code, so gating it on an isolation check would withhold the
    # one signal that is always available -- including on the machines where the
    # sandbox does not hold, which is exactly when a reader needs something.
    if a.do_build:
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
        # ------------------------------------------------ declared sources ---
        # Free, instant, and the only check that catches a package which never
        # fetched and now does -- proving that BEHAVIOURALLY needs a completed
        # build, and the build is what the sandbox stops.
        old_txt = aur.file_at(repo, old[0], "PKGBUILD")
        new_txt = aur.file_at(repo, new[0], "PKGBUILD")
        sf = sources.diff(old_txt, new_txt)
        print("\nDECLARED SOURCES  (static; no build, no sandbox)")
        print(sources.summarise(sf) if sf else "  " + sources.summarise(sf))
        if a.static:
            print("\nSTATIC ONLY. Nothing has been built.")
            return 0

        if not a.do_build:
            print("\nPLAN ONLY. Nothing has been built.")
            print("Re-run with --build to execute both PKGBUILDs in the sandbox.")
            print("This runs third-party build scripts; the sandbox has no route out")
            print("and no resolver socket, verified before each run.")
            return 0

        profs, builds = {}, {}
        for label, (sha, _d, ver) in (("baseline", old), ("newer", new)):
            d = aur.checkout_to(repo, sha, os.path.join(tmp, label))
            print("\nbuilding %s (%s)..." % (label, ver))
            p, meta = run_build(d, timeout=a.timeout)
            profs[label] = p
            ok = (not meta["timeout"]) and meta["rc"] in (0, None) and not looks_unbuilt(p)
            builds[label] = {"version": ver, "rc": meta["rc"],
                             "timed_out": meta["timeout"], "usable": ok}
            note = "timed out" if meta["timeout"] else "rc=%s" % meta["rc"]
            print("  %s  trace=%d B  %s" % (note, meta["trace_bytes"], summarise(p)))
            if not ok:
                print("  this build did not produce a usable profile")

        # Report what each build DID, separately from the comparison. A diff
        # cannot distinguish "the old version did not do this" from "the old
        # version did not build", and those mean opposite things.
        print("\nBUILD OUTCOMES")
        for label in ("baseline", "newer"):
            b = builds[label]
            print("  %-9s %-14s rc=%-5s %s" % (
                label, b["version"], b["rc"],
                "usable" if b["usable"] else "NOT USABLE -- excluded from the comparison"))

        v, why, _d = compare(profs["baseline"], profs["newer"], has_history=True)
        print("\nVERDICT: %s" % v)
        for w in why:
            print("  - %s" % w)
        if v == "unknown":
            print("\n  An old PKGBUILD may simply not reproduce today -- sources move,")
            print("  toolchains drift. That is not evidence about the new version.")
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
    ap.add_argument("--static", action="store_true",
                    help="diff the declared sources only; no build, no sandbox")
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
