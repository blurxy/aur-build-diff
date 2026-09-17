#!/usr/bin/env python3
"""A build sandbox that is actually isolated, and a check that proves it.

`bwrap --unshare-net` is not sufficient on a systemd host, and the failure is
silent. A new network namespace has no routes, so every TCP connect fails with
ENETUNREACH -- but if /run is bind-mounted in, the build can still reach
systemd-resolved over its UNIX socket at /run/systemd/resolve/io.systemd.Resolve
and resolve arbitrary names.

Measured on an Arch host, 2026-09-16: inside `bwrap --ro-bind / / --dev /dev
--unshare-net`, a TCP connect to 1.1.1.1:53 failed with "Network is unreachable"
while `getent hosts example.com` returned the real Cloudflare addresses.

That is not a cosmetic gap. DNS is the classic exfiltration channel -- a
hijacked PKGBUILD does not need a route out if it can ask a resolver to look up
<base64-of-your-ssh-key>.attacker.tld, because the query itself carries the data.
A sandbox that blocks routes but forwards the resolver socket is a sandbox that
blocks downloads and permits exfiltration, which is the wrong way round.

So: no blanket bind of /, and /run is a fresh tmpfs.
"""
import os, shutil, subprocess


def bwrap_argv(workdir, extra_ro=(), allow_dns=False, allow_net=False):
    """argv for an isolated build sandbox rooted at `workdir`.

    allow_net is for the FETCH PHASE ONLY and it is a different threat model, not a
    relaxation of this one. makepkg cannot download `source=()` with no route and no
    resolver, so with network off EVERY package aborts at "Retrieving sources" -- measured
    2026-09-16 on `downgrade`, where both builds reported rc=0 having downloaded nothing.

    Fetching on the HOST is not the alternative: `makepkg --verifysource` SOURCES the
    PKGBUILD, so the package's own code runs at parse time. Doing that outside a sandbox
    would hand arbitrary execution to the thing under examination, which is worse than the
    bug it fixes.

    So there are two sandboxes with different privileges, and the split is the point:
      FETCH  network ON, nothing but the package dir writable, no build phase reached
      BUILD  network OFF, sources already present, checksums verified
    Anything the BUILD phase does on the network is then genuinely the build reaching out,
    because the legitimate download already happened in a different jail. That removes the
    cargo/npm false-positive problem structurally instead of by heuristic -- and it is why
    --skipinteg can be dropped, so a tampered source fails a checksum instead of being
    waved through.
    """
    argv = [
        "bwrap",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/etc", "/etc",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib", "/lib64",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/bin", "/sbin",
        "--proc", "/proc",
        "--dev", "/dev",
        # tmpfs, NOT a bind: this is what closes the resolver-socket channel
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",
        "--bind", workdir, "/build",
        "--chdir", "/build",
        "--unshare-all",
        # --share-net re-shares ONLY the network namespace, after --unshare-all took
        # everything. Order matters to bwrap: the later flag wins.
    ] + (["--share-net"] if allow_net else []) + [
        "--new-session",          # no terminal to inject keystrokes into
        "--die-with-parent",
        "--setenv", "HOME", "/build",
        "--setenv", "PATH", "/usr/bin:/usr/local/bin",
    ]
    for p in extra_ro:
        if os.path.exists(p):
            argv += ["--ro-bind", p, p]
    if allow_dns:
        argv += ["--ro-bind", "/run/systemd/resolve", "/run/systemd/resolve"]
    if allow_net:
        # RESOLVER CONFIG FOR THE FETCH JAIL, and the reason it is needed is a consequence
        # of this file's own hardening. On Arch /etc/resolv.conf is a SYMLINK into
        # /run/systemd/resolve/, and /run here is a fresh tmpfs -- so the symlink dangles
        # and name resolution fails even with the network shared. Measured 2026-09-16:
        # --share-net alone gave `curl: (6) Could not resolve host: github.com`.
        #
        # Bind the FILE, never the directory. /run/systemd/resolve also contains the
        # io.systemd.Resolve UNIX SOCKET that this whole sandbox exists to keep out; binding
        # the directory to fix DNS would reopen the exfiltration channel in the one phase
        # that has network. A file bind cannot carry a socket.
        # AND IT CANNOT BE BOUND AT /etc/resolv.conf: that path is itself the symlink, and
        # bwrap refuses with "Can't mount on symlink destination". Measured -- the whole jail
        # failed to start, so the fetch silently never ran and the build aborted at download
        # exactly as before, which looked identical to having no fix at all.
        #
        # So satisfy the symlink instead of replacing it: recreate its TARGET PATH inside our
        # own tmpfs /run and bind just the file there. /run stays a tmpfs we control, the
        # directory contains nothing but this one read-only file, and the
        # io.systemd.Resolve socket still cannot exist in it -- which is the property the
        # build jail depends on and the fetch jail must not quietly surrender.
        real = os.path.realpath("/etc/resolv.conf")
        if os.path.isfile(real):
            link = os.path.normpath(os.path.join("/etc", os.readlink("/etc/resolv.conf"))) \
                   if os.path.islink("/etc/resolv.conf") else "/etc/resolv.conf"
            argv += ["--dir", os.path.dirname(link), "--ro-bind", real, link]
    return argv


PROBE = r"""
import socket, sys
out = []
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("1.1.1.1", 53)); out.append("tcp:ESCAPED")
except OSError:
    out.append("tcp:blocked")
finally:
    s.close()
try:
    socket.getaddrinfo("example.com", 80)
    out.append("dns:RESOLVED")
except Exception:
    out.append("dns:blocked")
print(" ".join(out))
"""


def verify(workdir="/tmp"):
    """Prove isolation rather than assume it. Returns (ok, detail)."""
    if not shutil.which("bwrap"):
        return False, "bwrap not installed"
    res = {}
    for label, allow in (("hardened", False), ("naive(--unshare-net only)", True)):
        argv = bwrap_argv(workdir, allow_dns=allow) + ["python3", "-c", PROBE]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            res[label] = (p.stdout or p.stderr).strip()
        except (OSError, subprocess.SubprocessError) as e:
            res[label] = "probe failed: %s" % e
    ok = res.get("hardened", "").startswith("tcp:blocked") and "dns:blocked" in res.get("hardened", "")
    return ok, res


if __name__ == "__main__":
    ok, detail = verify()
    for k, v in (detail.items() if isinstance(detail, dict) else []):
        print("  %-28s %s" % (k, v))
    print("\nhardened sandbox isolated:", ok)
    raise SystemExit(0 if ok else 1)
