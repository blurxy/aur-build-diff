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


def bwrap_argv(workdir, extra_ro=(), allow_dns=False):
    """argv for an isolated build sandbox rooted at `workdir`."""
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
