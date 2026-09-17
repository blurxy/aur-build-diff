#!/usr/bin/env python3
"""NEGATIVE CONTROL: importing PGP keys must not have disabled verification.

WHY THIS EXISTS. fetch_sources() now imports the keys a PKGBUILD declares in
validpgpkeys, inside the net-enabled jail, so the offline build phase can verify a
signature without reaching for a keyserver. That change makes strictly MORE packages
build -- which is indistinguishable from having turned verification off. rafiulbari-57
named the bar before this was written: a package with a known-bad signature must STILL
FAIL afterwards. If everything passes, the fix is `--skipinteg` wearing a different name,
and `--skipinteg` is the thing that was deliberately removed.

So the success criterion for the key-import change is NOT "more things build". It is
"the things that should fail still fail, and for the stated reason".

WHAT THIS PROVES AND WHAT IT DOES NOT. These three cases are local, deterministic, and
need no network: a good checksum passes, a wrong checksum fails, a bad signature fails.
Together they prove makepkg's verification still REJECTS after the change. They do NOT
prove the other half -- that a correctly signed package with a correctly imported key now
verifies OFFLINE, which is the entire point of the change and cannot be shown without a
real signed AUR package. That half is the pkgcacheclean run, and neither half is
sufficient alone: this file alone would pass if key import did nothing whatsoever.
"""
import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from runner import fetch_sources

PAYLOAD = b"aur-build-diff verification control payload\n"
GOOD = hashlib.sha256(PAYLOAD).hexdigest()
# A syntactically valid fingerprint that is not a real key. Deliberately not a real one:
# the control must not depend on a keyserver having any particular key tonight.
FAKE_FPR = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

TEMPLATE = """pkgname=%(name)s
pkgver=1
pkgrel=1
pkgdesc="aur-build-diff verification control"
arch=('any')
license=('MIT')
source=(%(source)s)
sha256sums=(%(sums)s)
%(extra)s
package() {
  install -Dm644 "$srcdir/payload.txt" "$pkgdir/usr/share/%(name)s/payload.txt"
}
"""


def make_case(root, name, sums, extra="", sig=None):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "payload.txt"), "wb") as fh:
        fh.write(PAYLOAD)
    source = "'payload.txt'"
    if sig is not None:
        with open(os.path.join(d, "payload.txt.sig"), "wb") as fh:
            fh.write(sig)
        source = "'payload.txt' 'payload.txt.sig'"
    with open(os.path.join(d, "PKGBUILD"), "w") as fh:
        fh.write(TEMPLATE % {"name": name, "source": source, "sums": sums, "extra": extra})
    return d


def run(label, d, expect_ok, expect_in_tail=()):
    """One case. Returns True if it behaved as required."""
    work = tempfile.mkdtemp(prefix="abd-verify-")
    try:
        shutil.copytree(d, os.path.join(work, "pkg"))
        meta = fetch_sources(work, timeout=180)
        ok = bool(meta.get("ok"))
        tail = meta.get("tail", "")
        keys = meta.get("keys", {})

        # Report the KEY OUTCOME on every case, including the ones where no key is declared.
        # A control that prints only its verdict cannot answer "did the import step even
        # run?", and that question is the difference between a passing control and a
        # control whose subject was never exercised.
        print("  %-22s ok=%-5s rc=%-5s keys(declared=%s imported=%d failed=%d observed=%s)"
              % (label, ok, meta.get("rc"), keys.get("declared"),
                 len(keys.get("imported") or []), len(keys.get("failed") or []),
                 keys.get("observed")))

        good = (ok == expect_ok)
        if not good:
            print("      REQUIRED ok=%s, GOT ok=%s" % (expect_ok, ok))
        missing = [s for s in expect_in_tail if s.lower() not in tail.lower()]
        if missing:
            # Failing for the wrong reason is not a pass. A checksum case that aborts
            # because bwrap could not start would satisfy `ok == False` while testing
            # nothing -- the same class of false green as a timeout counted as a verdict.
            print("      FAILED FOR THE WRONG REASON: tail lacks %r" % (missing,))
            good = False
        if not good:
            for line in (tail or "").strip().splitlines()[-8:]:
                print("      | %s" % line)
        return good
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    if not shutil.which("bwrap"):
        print("bwrap is required for this control; refusing to report a pass without it")
        return 2

    root = tempfile.mkdtemp(prefix="abd-verify-src-")
    try:
        print("negative control: verification must still REJECT after key import\n")
        cases = []

        # 1. GREEN. Without this the suite could pass by rejecting everything, which is the
        #    mirror-image failure of the one being guarded against.
        cases.append(("1 good checksum", run(
            "good-checksum",
            make_case(root, "abd-verify-good", "'%s'" % GOOD),
            expect_ok=True)))

        # 2. RED on integrity. Proves --skipinteg is really gone.
        #    THE EXPECTED STRING IS makepkg's ACTUAL WORDING, not a word that describes the
        #    concept. First written as "integrity", which makepkg never prints -- so the case
        #    reported FAILED FOR THE WRONG REASON on a rejection that was entirely correct.
        #    Kept as a note because the fix was to match the real message, NOT to drop the
        #    assertion: a tail check that passes on any failure cannot tell a checksum
        #    rejection from bwrap refusing to start.
        cases.append(("2 wrong checksum", run(
            "wrong-checksum",
            make_case(root, "abd-verify-badsum", "'%s'" % ("0" * 64)),
            expect_ok=False,
            expect_in_tail=("validity check",))))

        # 3. RED on signature -- THE CASE 57 ASKED FOR. A declared validpgpkeys entry the
        #    key import cannot satisfy, plus a .sig that is not a signature. makepkg must
        #    refuse. If this comes back ok=True, the key-import change has disabled
        #    signature verification and must be reverted rather than tuned.
        cases.append(("3 bad signature", run(
            "bad-signature",
            make_case(root, "abd-verify-badsig", "'%s' 'SKIP'" % GOOD,
                      extra="validpgpkeys=('%s')" % FAKE_FPR,
                      sig=b"-----BEGIN PGP SIGNATURE-----\nnot a signature\n"),
            expect_ok=False,
            expect_in_tail=("signature",))))

        print()
        bad = [n for n, good in cases if not good]
        for n, good in cases:
            print("  %s  %s" % ("PASS" if good else "FAIL", n))
        if bad:
            print("\nNEGATIVE CONTROL FAILED: %s" % ", ".join(bad))
            print("Do not ship the key-import change on this result.")
            return 1
        print("\nverification still rejects bad integrity AND bad signatures after key import.")
        print("This does NOT prove a good signature verifies offline -- see the module "
              "docstring; that is the real-package half.")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
