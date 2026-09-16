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


def build(pkgbuild_dir, timeout=600, allow_dns=False, keep=False):
    """Run makepkg on a PKGBUILD in an isolated sandbox. Returns (profile, meta)."""
    work = tempfile.mkdtemp(prefix="abd-")
    src = os.path.join(work, "pkg")
    shutil.copytree(pkgbuild_dir, src)
    trace = os.path.join(work, "trace.txt")

    if not shutil.which("strace"):
        raise RuntimeError("strace is required for the v1 capture layer")

    inner = ("cd /build/pkg && "
             "strace -f -qq -s 256 -e %s -o /build/trace.txt "
             "makepkg --nodeps --noconfirm --skipinteg 2>&1 | tail -40" % TRACED)
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
    meta["trace_bytes"] = len(text)
    prof = parse_strace(text)
    if not keep:
        shutil.rmtree(work, ignore_errors=True)
    else:
        meta["workdir"] = work
    return prof, meta


def summarise(prof):
    return {k: len(v) for k, v in prof.items()}
