#!/usr/bin/env python3
"""Build a PKGBUILD inside the sandbox and record what it did.

strace is the v1 capture layer because it needs no privileges, no kernel module
and no eBPF toolchain -- it runs on whatever machine the user already has. It
also costs 20-50x on a real compile, which is fine for a one-off audit of a
package you are about to install and wrong for a pre-install hook on every
upgrade. A pcap on the sandbox veth plus auditd exec events is the faster v2.
"""
import os, sys, shutil, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sandbox import bwrap_argv
from profile import parse_strace

TRACED = "trace=connect,execve,openat,open,sendto,socket"

# THE KEYRING MUST LIVE IN THE SHARED WORKDIR, NOT IN THE JAIL'S HOME.
# This is the whole mechanism. /build is the one directory both phases see, because both
# bind the same host workdir. A keyring anywhere else -- $HOME, /root/.gnupg, a tmpfs --
# is destroyed when phase 1's jail exits, so the import "succeeds" and phase 2 still has
# no key. That failure mode is invisible: gpg reports success, makepkg later reports
# "unknown public key", and nothing connects the two.
GNUPGHOME = "/build/gnupg"

# Imported in phase 1 because THIS IS THE ONLY PHASE WITH NETWORK, and a keyserver fetch
# is a network operation. Leaving it implicit in phase 2 was a real defect in the
# two-phase design (diagnosed by rafiulbari-0e, 2026-09-17): the offline build reaches for
# a keyserver it cannot contact and hangs until the timeout. Measured on pkgcacheclean --
# `unknown public key 019A7474297D8577`, whose fingerprint the PKGBUILD itself declares in
# validpgpkeys. The jail had the network AND the fingerprint and never put them together.
#
# SOURCING THE PKGBUILD EXECUTES IT. That is not a new exposure: `makepkg --verifysource`
# on the next line sources the same file in the same jail, so parse-time code already runs
# here by design. Doing it on the HOST to read validpgpkeys would be the unacceptable
# version, which is why this runs inside.
#
# A KEY IMPORT FAILURE IS NOT A FETCH FAILURE and must not be reported as one. An
# unreachable keyserver, a revoked key and a PKGBUILD with no validpgpkeys at all are
# three different states; makepkg's own signature check is what decides whether the build
# may proceed. This step only makes the decision POSSIBLE offline -- it never makes it.
_KEY_IMPORT = r'''
export GNUPGHOME=%s
install -d -m 700 "$GNUPGHOME"
_keys=$( (source ./PKGBUILD >/dev/null 2>&1; printf '%%s\n' "${validpgpkeys[@]:-}") 2>/dev/null \
         | grep -Ex '[0-9A-Fa-f]{8,40}' || true )
if [ -z "$_keys" ]; then
  echo "ABD_KEY_NONE"
else
  for _k in $_keys; do
    if gpg --batch --quiet --keyserver hkps://keyserver.ubuntu.com --recv-keys "$_k" >/dev/null 2>&1; then
      echo "ABD_KEY_OK $_k"
    else
      echo "ABD_KEY_FAIL $_k"
    fi
  done
fi
''' % GNUPGHOME


def fetch_sources(workdir, timeout=300):
    """Download `source=()` in a NET-ENABLED jail, so the BUILD jail can stay offline.

    WHY THIS EXISTS. With no route and no resolver, makepkg cannot retrieve sources, so
    EVERY package with a remote source aborts at "Retrieving sources" -- which is nearly all
    of them. Measured 2026-09-16 on `downgrade`: four failed `curl: (6) Could not resolve
    host` retries, then "ERROR: Failure while downloading ... Aborting". Nothing was built,
    and before the pipefail fix the runner called that rc=0.

    WHY NOT FETCH ON THE HOST. `makepkg --verifysource` SOURCES the PKGBUILD, so the
    package's own code executes at parse time. Running that outside a sandbox hands
    arbitrary execution to the thing under examination -- strictly worse than the bug.

    THE RESIDUAL RISK, STATED RATHER THAN HIDDEN. This jail has network AND runs the
    package's parse-time code, so a hostile PKGBUILD can talk to the internet here. What it
    cannot do is reach anything worth taking: no $HOME, no ~/.ssh, no ~/.secrets, no blanket
    bind of /, /run a fresh tmpfs. The containment is "network but nothing to exfiltrate",
    not "no network". That is a genuine weakening of one phase in exchange for the build
    phase becoming meaningful at all, and the split is what buys the real prize -- any
    network activity seen during the BUILD is then unambiguously the build reaching out,
    because the legitimate download already happened somewhere else. No heuristic needed to
    excuse cargo and npm.
    """
    inner = ("set -o pipefail\ncd /build/pkg || exit 1\n" + _KEY_IMPORT +
             "\nexport GNUPGHOME=" + GNUPGHOME + "\n"
             "makepkg --verifysource --nodeps --noconfirm 2>&1 | tail -30")
    argv = bwrap_argv(workdir, allow_net=True) + ["bash", "-lc", inner]
    meta = {"timeout": False, "rc": None, "tail": ""}
    full = ""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        meta["rc"] = p.returncode
        full = p.stdout or ""
        meta["tail"] = full[-1500:]
    except subprocess.TimeoutExpired:
        meta["timeout"] = True
    meta["ok"] = meta["rc"] == 0 and not meta["timeout"]

    # PARSE THE MARKERS FROM THE FULL STDOUT, NOT FROM meta["tail"].
    # The markers are printed BEFORE makepkg runs and `tail` keeps the LAST 1500 chars, so a
    # chatty package would push them out of the window -- and the result would not be an
    # error, it would be `declared=True, imported=[]`: exactly the reading that means "keys
    # were needed and none arrived". A successful import would report as the failure it is
    # designed to detect. Caught before this was ever run; it is the same absence-reads-as-an
    # -answer shape as the digest file whose non-emptiness stood in for its item count.
    meta["keys"] = {
        "declared": "ABD_KEY_NONE" not in full,
        "imported": [l.split()[1] for l in full.splitlines() if l.startswith("ABD_KEY_OK ")],
        "failed": [l.split()[1] for l in full.splitlines() if l.startswith("ABD_KEY_FAIL ")],
        # Truthful under truncation: if the markers were lost we say so rather than infer.
        "observed": ("ABD_KEY_NONE" in full or "ABD_KEY_OK " in full
                     or "ABD_KEY_FAIL " in full),
    }
    return meta


def build(pkgbuild_dir, timeout=600, allow_dns=False, keep=False):
    """Run makepkg on a PKGBUILD in an isolated sandbox. Returns (profile, meta)."""
    work = tempfile.mkdtemp(prefix="abd-")
    src = os.path.join(work, "pkg")
    shutil.copytree(pkgbuild_dir, src)
    trace = os.path.join(work, "trace.txt")

    # PHASE 1, DIFFERENT PRIVILEGES: network on, nothing worth stealing reachable.
    # Sources land in the same /build/pkg the offline phase will use, so phase 2 starts at
    # prepare() with everything present.
    fetch = fetch_sources(work, timeout=min(timeout, 300))

    if not shutil.which("strace"):
        raise RuntimeError("strace is required for the v1 capture layer")

    # set -o pipefail is load-bearing: without it the exit status is tail's, so
    # an aborted makepkg reported rc=0 and the runner called a failed build
    # successful. Measured on yay-bin, which aborts at the download step inside
    # a no-network sandbox and still returned 0.
    # GNUPGHOME POINTS AT PHASE 1's KEYRING. Without this line the import above is dead
    # work: gpg in the offline jail looks in a fresh HOME, finds nothing, and makepkg
    # reaches for a keyserver it cannot contact -- the exact hang this change exists to fix.
    # The two lines are one mechanism and must not be separated.
    inner = ("set -o pipefail; export GNUPGHOME=" + GNUPGHOME + "; cd /build/pkg && "
             "strace -f -qq -s 256 -e %s -o /build/trace.txt "
             # --skipinteg IS GONE ON PURPOSE. It was needed only because the source
             # could never arrive; now that phase 1 fetches it, checksums are verifiable,
             # and a tampered source should fail integrity rather than be waved through by
             # the tool that exists to inspect it.
             "makepkg --nodeps --noconfirm 2>&1 | tail -40" % TRACED)
    argv = bwrap_argv(work, allow_dns=allow_dns) + ["bash", "-lc", inner]
    meta = {"timeout": False, "rc": None, "tail": ""}
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        meta["rc"] = p.returncode
        meta["tail"] = (p.stdout or "")[-1500:]
    except subprocess.TimeoutExpired:
        meta["timeout"] = True

    tp = os.path.join(work, "trace.txt")
    text = ""
    if os.path.exists(tp):
        with open(tp, errors="replace") as fh:
            text = fh.read()
    meta["fetch"] = fetch
    # A FETCH FAILURE IS NOT A BUILD RESULT. Without this the offline build aborts at
    # "Retrieving sources" exactly as before and the caller cannot tell why.
    if not fetch.get("ok"):
        meta["unfetched"] = True
    meta["trace_bytes"] = len(text)
    prof = parse_strace(text)

    # Attach provenance TO THE PROFILE. A build outcome kept beside the data
    # gets separated from it: a caller passes the dict on, the outcome stays
    # behind, and a failed build is compared as though it were a clean one.
    tail = meta.get("tail", "")
    aborted = ("==> ERROR:" in tail) or ("Aborting" in tail)
    fetch_failed = ("Failure while downloading" in tail
                    or "Could not resolve host" in tail)
    prof["_build"] = {
        "rc": meta["rc"],
        "timed_out": meta["timeout"],
        "aborted": aborted,
        "fetch_failed": fetch_failed,
        "usable": (not meta["timeout"]) and meta["rc"] == 0 and not aborted,
    }
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    else:
        meta["workdir"] = work
    return prof, meta


def summarise(prof):
    """Distinct values AND total occurrences.

    Reporting len() alone rendered sixteen failed resolver attempts as
    "connects: 1", which reads as "basically nothing happened". Distinct
    endpoints are the right thing to DIFF on and the wrong thing to show alone.
    """
    out = {}
    for k, v in prof.items():
        if k.startswith("_") or not isinstance(v, dict):
            continue
        n, total = len(v), sum(v.values())
        out[k] = "%d" % n if n == total else "%d/%d" % (n, total)
    return out
