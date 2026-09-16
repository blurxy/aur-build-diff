# aur-build-diff

Build an AUR package twice — this version and the last known good one — in an
isolated sandbox, and diff what each one actually *does*.

> **Status: core prototype.** The sandbox and its isolation proof are real and
> reproducible (`python src/sandbox.py`); the behaviour differ is real and
> self-tested (`python src/profile.py`). Driving `makepkg` over real AUR git
> history is not wired up yet.

## Why dynamic, when good static scanners exist

Every popular PKGBUILD scanner is static, and the best of them says so on
purpose. [ks-aur-scanner](https://github.com/KiefStudioMA/ks-aur-scanner)
(~100★, Rust): *"sandboxed dynamic analysis is out of scope by design (that's
what keeps it safe to run)."* [aur-malware-check](https://github.com/lenucksi/aur-malware-check)
(~2.2k★) is an IOC list for the June 2026 "Atomic Arch" incident, not a general
detector. [aurscan](https://github.com/manticore-projects/aurscan) (~147★) asks
an LLM, which is non-deterministic and itself promptable by the PKGBUILD it is
reading. [archcanary](https://github.com/musqz/archcanary) does static analysis
plus **post-install** runtime monitoring — closest in spirit, but it watches the
system after the fact rather than the build as it happens.

None of them do ground-truth, version-over-version **build-time** behavioural
diffing. That is the gap.

## The finding that shaped the sandbox

`bwrap --unshare-net` is not sufficient on a systemd host, and it fails silently.

A new network namespace has no routes, so every TCP connect fails with
`ENETUNREACH`. But if `/run` is bind-mounted in, the build can still reach
`systemd-resolved` over its **unix socket** and resolve arbitrary names.
Measured on Arch, 2026-09-16:

| sandbox | TCP connect | DNS |
|---|---|---|
| `--ro-bind / /` + `--unshare-net` | blocked | **example.com → real Cloudflare IPs** |
| hardened (tmpfs `/run`, no blanket bind) | blocked | blocked |

That is the wrong way round. DNS is the classic exfiltration channel: a hijacked
PKGBUILD does not need a route out if it can ask a resolver to look up
`<base64-of-your-ssh-key>.attacker.tld` — **the query is the data**. A sandbox
that blocks downloads while forwarding the resolver socket stops the payload and
permits the theft.

`src/sandbox.py` proves isolation instead of assuming it, and runs the naive
profile alongside as a control.

## The hard part is the baseline, not the sandbox

Legitimate builds already fetch from the network (cargo, npm, go), write all over
the filesystem, and exec compilers. "This build touched the network" is a
false-positive firehose.

What survives is a **change against the package's own history**: this PKGBUILD
has not contacted `registry.npmjs.org` in its last six releases and now it does.
`src/profile.py` extracts `{connects, execs, writes-outside-build-tree,
resolved-names}` from a trace and reports one-directionally — a build that
*stopped* calling a host is not interesting; one that *started* is.

Known limitations, stated rather than discovered later:

- **`strace -f` costs 20–50× on a real compile.** Acceptable for a one-off audit,
  wrong for "run this before every install". A pcap on the sandbox veth plus
  auditd exec events is the faster v2.
- **Rebuilding a historical version may not reproduce** — upstream URLs move,
  toolchains drift. When the last-known-good build fails, there is no baseline,
  and the honest answer is to fall back to the `source=()` allowlist heuristic
  and say so, not to flag everything.
- **First-seen packages have no history.** The verdict is `unknown`, not
  `suspicious` — every AUR package is first-seen once.
- With no egress, an exfil attempt appears as a **refused connect**, not a
  completed download. That is still a clean catch, and claiming to observe the
  full download-and-execute chain would require a local sinkhole serving the
  captured payload — a bigger, disclosed setup.

## It works end to end

Real `makepkg`, real `strace`, real sandbox. The pair below is synthetic — content
written for this test, so nothing untrusted executes — and differs only by three
added lines that resolve a name and reach out:

```
build      rc   execs  connects   writes-outside
clean       0      28         0                3
hijacked    0      30         1                3

VERDICT: changed
  - new outbound endpoints: 127.0.0.1:53
  - executed binaries absent from the previous build: /usr/bin/curl, /usr/bin/getent

control (clean vs clean): unchanged
```

Three details in that output are the whole design:

**`writes_outside: 3` in BOTH builds.** makepkg legitimately writes outside the
build tree. A rule like "wrote outside $srcdir = suspicious" would fire on every
package ever built. The diff is one-directional against the package's own
previous behaviour, so identical noise cancels and only the *change* survives.

**The connect is to `127.0.0.1:53`, not to example.com.** The sandbox has no
route out, so the exfil attempt appears as a refused resolver call rather than a
completed download. That is still a clean catch, and it is what the tool can
honestly claim to observe — building the full download-and-execute chain would
need a local sinkhole serving the captured payload, which is a larger and
disclosed setup.

**The control is silent.** A differ that flags everything is not a differ.

### Against a real package

`src/aur.py` reads a package's own git history — every AUR package is a git repo
whose commits are successive PKGBUILDs — which is where the baseline comes from:

```
exists(yay-bin): True
  13e0a4754d  2026-06-19  13.0.1-1
  f559115d63  2026-06-17  13.0.0-1
  d091abaa64  2026-06-07  12.6.0-1
  1751e24c43  2025-12-14  12.5.7-1
```

Metadata only — nothing above was built. Building a real package is a deliberate
act the user takes, not something a README demo does for them.

## Run it

```
python src/sandbox.py     # proves the sandbox is isolated, with a control
python src/profile.py     # self-test of the differ on synthetic traces
```

Nothing here downloads or executes a real package yet.

## License

MIT.
