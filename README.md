# aur-build-diff

Build an AUR package twice — this version and the last known good one — in an
isolated sandbox, and diff what each one actually *does*.

> **Status: it builds real packages and detects a real injected change. Read
> [What is broken](#what-is-broken) before trusting a verdict.**
> The sandbox and its isolation proof are reproducible
> (`aur-build-diff --check-sandbox`), the differ is self-tested, and
> `src/selftest_detect.py` is a positive control: it injects a change into a real
> build and asserts the tool goes red, because a suite that has never been red
> proves nothing.
>
> `--static` diffs what a PKGBUILD *declares* in **1.3 seconds** with no build,
> no sandbox and no root — and it is the only check that catches a package which
> never fetched and now does, because proving that behaviourally needs a
> completed build and completing the build is what the sandbox prevents.
>
> The defect that made this unusable — the sandbox blocked DNS, `makepkg` needs
> DNS to fetch `source=()`, so almost no package could build and two sessions got
> a confident `unchanged` for builds that never happened — is **fixed**, by
> splitting fetch and build into two jails with different privileges. What
> remains open is **defect 7**: an attribution bug where every number is correct
> and the sentence they support is wrong.

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

## What is broken

Two peer sessions ran this on `yay-bin` and `downgrade` and both got:

```
BUILD OUTCOMES
  baseline  12.0.1-1   rc=0   usable
  newer     12.0.2-1   rc=0   usable
VERDICT: unchanged  -- no behavioural change
```

Both builds had died at `curl: (6) Could not resolve host: github.com`. Four
separate defects stacked to produce that confident green:

1. ~~**The sandbox blocks DNS; `makepkg` needs DNS.**~~ **FIXED.** `source=()` is a
   remote URL for nearly every AUR package, so the build aborted before reaching
   any code worth judging — structurally, for every package equally. Fixed by
   splitting the run into two jails with different privileges (see *The two-phase
   build* below). Fixed by the session `alienware-main-chat`.
2. **`rc` was `tail`'s exit status, not `makepkg`'s.** The inner command piped
   through `tail -40` with no `pipefail`, so a failed build reported `rc=0`
   forever. `bash -lc 'false | tail -40'` returns 0; with `set -o pipefail`, 1.
3. **The "did it build?" guard keyed on emptiness, and the profile wasn't empty.**
   A build that dies while downloading has already exec'd bash, makepkg, curl and
   the retry loop — ten distinct binaries, 471 calls. The guard was satisfied by
   the harness's own machinery.
4. **A failed build manufactures a network profile out of its own failure.**
   Sixteen connects to the stub resolver, from curl's retries. An empty profile
   at least *looks* wrong; this one looks like a real build and is entirely noise.
5. **Every relative path counted as "outside the build tree".**
   `not path.startswith(("/build", ...))` is true for any non-absolute path, so
   `.PKGINFO`, `.BUILDINFO` and `.MTREE` — written by makepkg inside `$pkgdir` —
   were flagged on every build ever run. They cancelled in the diff while both
   sides produced them, then surfaced as a security-sounding red the moment one
   side had one extra. This is defect 4 inverted: failure artefacts manufacture a
   false *green*, relative paths a false *red*.
6. **A refused write counted the same as a successful one.** The parser read the
   path and flags and never the syscall's return value. Inside this sandbox
   `/usr` and `/etc` are read-only binds, so a *successful* write outside the
   build tree is nearly impossible by construction — almost everything in that
   field was an attempt. The fix is not to discard the failures: an **attempt**
   to write outside the build tree is better signal than a success. The defect
   was the word "wrote".

Fixed: `pipefail`; build provenance attached to the profile rather than kept
beside it; `diff()` raises `NoBaseline` rather than comparing against a build
that did not happen; resolver attempts, relative writes and *refused* writes each
given their own namespace instead of being filtered; `summarise()` shows
distinct/total so 16 attempts no longer render as "1"; the verdict now says
**WROTE** or **ATTEMPTED and was refused**, which are different findings.

The recurring shape in 4, 5 and 6: a field populated with things that are not
what the field claims to hold. The repair is always the same — give the different
thing its own namespace rather than filtering it out, because filtering discards
signal and leaves the name still lying.

### Packages that build today, without the fetch phase

Any package whose `source=()` is local files needs no network, so it completes in
the sandbox as it stands. This is the regression corpus (found by `rafiulbari-0e`):

```
bash-pipes               13 revs   source=() empty entirely
mkinitcpio-firmware      12 revs
pacman-cleanup-hook       9 revs
systemd-boot-pacman-hook  8 revs
update-grub               3 revs
```

Real end-to-end run, and the first correct verdict the tool produced:

```
pacman-cleanup-hook  1.0-8 -> 1.1-1
  baseline  29/504 execs, writes_relative 3/4
  newer     29/504 execs, writes_relative 4/5
  VERDICT: unchanged
```

The extra relative write is visible in the profile and correctly not a finding.

7. **Right field, right count, wrong attribution — and nothing is filterable.**
   `mkinitcpio-firmware` 1.0.0 -> 1.6.0 correctly read `changed`, naming
   `/usr/bin/file`, `/usr/bin/ln`, `/usr/bin/readelf` and `/usr/bin/install` as
   newly executed. Only `install` appears in the newer PKGBUILD. The other three
   are makepkg's own tidy/strip machinery, which runs *because* the package
   gained a `package()` function — so they appeared **because of** the change
   rather than **as part of** it. Every one of those execs really happened. The
   data is correct and it licenses a false inference: "executed
   `/usr/bin/readelf`" is a sentence a hijacked PKGBUILD would earn, and here it
   means the package finally installs a file. This is worse than defects 4–6 —
   those produce noise you can filter, this is a **true statement supporting a
   wrong conclusion**, so no filter can reach it.

   The obvious fix does not work. `fakeroot` looked like a clean phase boundary,
   but measured on that build: `readelf` at execve 468 (after fakeroot at 229),
   while `file` at 224 and `ln` at 223 land *before* it — they are makepkg's
   extraction machinery, not its packaging phase. Attribution needs to separate
   harness from subject some other way, and a heuristic would be the seventh
   guess in one evening. Left open deliberately. Found by `rafiulbari-0e`.

8. **The baseline guard was applied to one side of a two-sided comparison.**
   `diff()` refused an unusable *old* profile and never checked the *new* one.
   Measured on `pkgcacheclean` 1.9.0-2 → 1.9.0-3: the newer build timed out at
   240s while fetching, the CLI printed `NOT USABLE — excluded from the
   comparison`, and **two lines later** printed

   ```
   VERDICT: changed
     - executed binaries absent from the previous build:
       /usr/bin/gpg, /usr/lib/gnupg/keyboxd
   ```

   derived from that very build. The intuition that an incomplete *new* profile
   can only lose findings is wrong, and that is why this produced a red rather
   than a quiet under-report: a failure path runs binaries a success path never
   reaches — makepkg reaching for signature verification while the fetch hung —
   so the failure's own machinery reads as newly introduced behaviour. The guard
   was in the right place, for the right stated reason, and covered one of two
   arguments. Fixed: `diff()` raises `NoBaseline` or `NoSubject`, and the
   self-test in `src/profile.py` asserts both sides. Found by `rafiulbari-0e`.

**Not fixed: defect 7.** Read a `changed` that names makepkg's own tools (`file`,
`ln`, `readelf`, `strip`, `bsdtar`, `fakeroot`) as "this package started producing
output", not as "this package started inspecting binaries".

## The declaration diff: the check that actually catches it

The headline case for a tool like this is a package that has not touched the
network in six releases and suddenly does. `rafiulbari-0e` went looking for
exactly that and found it: `pkgcacheclean` carried
`source=($pkgname.c $pkgname.8)` — two local files compiled in place — for six
revisions, then commit `41aa13ae` switched to a GitHub release tarball.

**The behavioural differ could not report it, and cannot.** Demonstrating
"this version fetches" requires a *completed* build, and completing the build is
what the sandbox exists to prevent. The evidence for the finding destroys the
run that would produce it. Measured: that build times out even with the
two-phase fetch and a 300s budget. What came out instead was a confident red
about `/usr/bin/gpg` — which was [defect 8](#what-is-broken).

`src/sources.py` reads the PKGBUILD instead. No build, no sandbox, no `makepkg`:

```console
$ aur-build-diff pkgcacheclean --static
package   pkgcacheclean
newer     41aa13ae07  2019-05-26  1.9.0-3
baseline  904f275e16  2017-09-07  1.9.0-2

DECLARED SOURCES  (static; no build, no sandbox)
  [high  ] the previous revision declared NO remote source; this one fetches 2:
           https://github.com/dbermond/pkgcacheclean/archive/v1.9.0.tar.gz,
           .../releases/download/v1.9.0/pkgcacheclean-1.9.0.tar.gz.asc
  [medium] signing key changed to one the previous revision did not trust:
           3FFA6AB7B69AAE6CCA263DDE019A7474297D8577
```

**1.3 seconds**, most of it the git clone.

### It discriminates, which is the only thing that makes a finding mean anything

Across `pkgcacheclean`'s whole history it fires on **one** transition and is
silent on the other five. Three unrelated packages are silent too:

| comparison | result |
|---|---|
| `pkgcacheclean` 1.9.0-2 → 1.9.0-3 | **1 finding** — went remote |
| `pkgcacheclean` ×5 other releases | clean |
| `downgrade`, `yay-bin`, `update-grub` | clean |

### What it reads

`went_remote` (declared no remote source, now does) · `new_host` ·
`checksum_changed_same_url` (the bytes at an unchanged address changed) ·
`integrity_skipped` · `sums_removed` · `install_script` (gained a scriptlet,
which runs as **root** on the installing machine, outside anything this sandbox
observes) · `pgpkey_added` / `pgpkey_removed`.

### What it cannot do, stated because a static check quiet about its blind spots is the failure this repo keeps finding

- It reads the **declared** array. A PKGBUILD that runs `curl` inside `build()`
  is invisible here and visible to the behavioural differ. The two are
  complementary in both directions, not ranked.
- Variable expansion is shallow and textual. Anything computed by shell is left
  alone and reported as `unresolved` rather than guessed at.
- It fetches nothing, so it cannot tell you whether a URL resolves or serves
  what its checksum claims.

### Two defects in this module, both found by real data and neither by my own fixtures

Seven hand-written self-tests passed while both of these were live:

1. **`source=("name"::"url")` with both halves quoted parsed as two entries**,
   and the URL kept its quote marks, so `startswith("https://")` was false and
   it was classified **local**. On the real `pkgcacheclean` the release tarball
   was not counted as a remote source at all — only its detached `.asc`.
2. **`checksum_changed_same_url` fired on local files.** A local file's checksum
   changing is what a version bump *is*. It fired on two of three ordinary
   releases and called them "the bytes at an unchanged address changed" — true
   of a local file in the least alarming possible way.

Both now have regression tests. The lesson is the one this repo keeps
relearning: fixtures test the code against the author's model of the world, and
it is the model that is wrong.

## The two-phase build

Defect 1 was the architectural one: the sandbox existed to deny network, and
`makepkg` cannot fetch `source=()` without it. The fix is two jails with
different privileges rather than one jail with a compromise.

```
FETCH   network ON, nothing worth taking reachable.  makepkg --verifysource
BUILD   sources already present, no route, no resolver.
```

Fetching on the host was never an option: `makepkg --verifysource` **sources** the
PKGBUILD, so the package's own code runs at parse time. Doing that unsandboxed
hands arbitrary execution to the thing under examination. The residual risk is
stated rather than hidden — the fetch jail has network *and* runs parse-time
code, and what contains it is that there is nothing there to take: no `$HOME`,
no `~/.ssh`, no blanket bind of `/`.

Two things that were not obvious:

- **`/etc/resolv.conf` on Arch is a symlink into `/run`**, and `/run` is the
  sandbox's own fresh tmpfs, so the symlink dangles and DNS fails *even with*
  `--share-net`. The hardening breaks legitimate resolution as a side effect.
- **It cannot simply be bound at `/etc/resolv.conf`** — that path *is* the
  symlink, and bwrap refuses with `Can't mount on symlink destination`. The jail
  then fails to **start**, which looks byte-for-byte identical to having no fix
  at all. Fixed by satisfying the symlink instead of replacing it: recreate its
  target path inside our own tmpfs and bind only the file there, then remount
  that directory read-only.

Verified, both jails, independently of the session that wrote it:

```
FETCH (net)     dir write:DENIED   entries: stub-resolv.conf   sockets:0   dns:RESOLVED
BUILD (no net)  dir write:DENIED   entries: (none)             sockets:0   dns:blocked
```

The `sockets:0` line is the one that matters. The host has
`/run/systemd/resolve/io.systemd.Resolve` and `.Monitor`; `find /run -type s`
inside the net-enabled fetch jail returns nothing. The fetch phase gets DNS
without getting the unix socket this sandbox exists to keep out.

**Why this makes the tool stronger, not merely working.** Once the legitimate
fetch has already happened in the other jail, **any** name resolution during the
build is anomalous by construction. Measured on `downgrade`:

| | before | after |
|---|---|---|
| trace | 450,832 B | 2,473,152 B |
| execs | 10 / 224 | 35 / 664 |
| `resolver_attempts` | 1 / 16 | **0** |
| verdict | `unchanged` | `unchanged` |

Both verdicts read `unchanged` and they mean opposite things: the first pair is
two identical *failures*, the second is two identical *successes*. That kills the
cargo/npm false-positive firehose structurally instead of by heuristic, and it
let `--skipinteg` go — so a tampered source now fails a checksum instead of
being waved through by the tool built to inspect it.

### Can it detect anything?

Five corpus packages all returning `unchanged` is not evidence — a suite that has
never been red proves nothing. `python src/selftest_detect.py` builds a real
PKGBUILD, then the same one plus an injected `build()` block, and asserts the
difference is found:

```
baseline  execs 30/505  resolver_attempts 0    writes_denied 0
injected  execs 33/509  resolver_attempts 1/4  writes_denied 1

VERDICT: changed
  - ATTEMPTED to write outside the build tree and was refused:
      /usr/lib/selftest-should-be-refused
  - executed binaries absent from the previous build:
      /usr/bin/env, /usr/bin/getent, /usr/bin/true

control (real build vs itself): unchanged
```

The baseline carries makepkg's genuine 400-grep machinery, so this also shows the
injected signal survives being diffed against real noise.

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
aur-build-diff --check-sandbox      # prove isolation holds here, with a control
aur-build-diff <pkg> --history      # list the package's PKGBUILD revisions
aur-build-diff <pkg>                # plan only -- shows what WOULD be built
aur-build-diff <pkg> --build        # actually build both versions and diff
```

**Building is opt-in and that is deliberate.** `makepkg` executes arbitrary code
from a PKGBUILD, and the entire premise of this tool is that you do not yet know
whether that code is hostile. The sandbox is real and is re-verified before every
run — but a sandbox is a mitigation, not a permission slip. The default prints a
plan and executes nothing.

It also refuses to build at all if `--check-sandbox` does not pass on your
machine, rather than proceeding with weaker isolation than it claims.

When the baseline build fails — and old PKGBUILDs do fail, sources move and
toolchains drift — the verdict is `unknown`, not `clean`. A comparison against a
build that did not happen is not a comparison.

Self-tests, no network or package needed:

```
python src/sandbox.py          # isolation, hardened vs permissive
python src/profile.py          # the differ, on synthetic traces
```

## License

MIT.
