#!/usr/bin/env python3
"""What a PKGBUILD DECLARES, diffed across two revisions.

WHY THIS EXISTS ALONGSIDE THE BEHAVIOURAL DIFF, and it is not redundancy.

The headline case for a tool like this is a package that has not touched the
network in its last six releases and suddenly does. rafiulbari-0e went looking
for exactly that and found it: `pkgcacheclean` carried
`source=($pkgname.c $pkgname.8)` -- two local files compiled in place -- for six
revisions, then commit 41aa13ae switched to a GitHub release tarball.

The behavioural differ could not report it. Demonstrating "this version fetches"
requires running a build that the sandbox is designed to prevent from
completing, so the evidence for the finding destroys the run that would produce
it. Measured: the build timed out even with the two-phase fetch and a 300s
budget. What came out instead was a confident red about /usr/bin/gpg.

This module catches it by reading the PKGBUILD. One second, no sandbox, no
build, no makepkg. It is strictly weaker evidence -- a declaration is a claim
about behaviour, not behaviour -- and it is available when the strong evidence
is not, which is most of the time.

WHAT IT CANNOT DO, stated up front because a static check that is quiet about
its blind spots is the failure this repo keeps finding:

  * It reads the declared array. A PKGBUILD that downloads inside build() with
    curl is invisible here and visible to the behavioural differ. The two are
    complementary in both directions, not ranked.
  * Variable expansion is deliberately shallow -- $pkgname, $pkgver, $_pkgname
    and the ${...} forms, substituted textually. Anything computed by shell
    (command substitution, arrays, conditionals) is left as-is and the host is
    reported as unresolved rather than guessed at.
  * It does not fetch anything, so it cannot tell you whether a URL resolves,
    is reachable, or serves what its checksum claims.
"""

import re
import sys


REMOTE_SCHEMES = ("http://", "https://", "ftp://", "ftps://",
                  "git://", "git+", "svn://", "svn+", "hg+", "bzr+", "rsync://")

_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def _assignments(text):
    """Scalar assignments, for shallow variable expansion."""
    out = {}
    for m in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=([^\s(#][^\n#]*)", text, re.M):
        v = m.group(2).strip().strip('"').strip("'")
        if "(" not in v:
            out[m.group(1)] = v
    return out


def _expand(s, env, depth=3):
    """Substitute $pkgname / ${pkgver} textually, a few levels deep.

    Deliberately not a shell. A value this cannot resolve keeps its literal
    $name, and callers report that as unresolved rather than inventing a host.
    """
    for _ in range(depth):
        new = _VAR.sub(lambda m: env.get(m.group(1), m.group(0)), s)
        if new == s:
            break
        s = new
    return s


def _array(text, name):
    """Extract a bash array by name, including arch-suffixed variants.

    `source=()`, `source_x86_64=()` and `source_aarch64=()` are all sources;
    treating only the bare name as authoritative would miss a URL added to the
    arch-specific array alone.
    """
    items = []
    for m in re.finditer(r"^\s*%s(_[a-z0-9_]+)?\s*=\s*\(" % re.escape(name),
                         text, re.M):
        i = m.end()
        depth, buf = 1, []
        while i < len(text) and depth:
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if not depth:
                    break
            buf.append(c)
            i += 1
        body = re.sub(r"#[^\n]*", " ", "".join(buf))   # strip comments
        items += _tokens(body)
    return items


def _tokens(body):
    """Split a bash array body into entries, honouring quotes INSIDE an entry.

    A naive "quoted string OR run of non-space" tokeniser splits the very form
    this module exists to read:

        source=("${pkgname}-${pkgver}.tar.gz"::"https://host/v${pkgver}.tar.gz")

    Both halves of `name::url` are separately quoted, so the naive version
    emitted two entries -- a bare filename and a URL that kept its own quote
    marks, which then failed `startswith("https://")` and was classified LOCAL.
    Measured on the real pkgcacheclean 1.9.0-3: the release tarball was not
    counted as a remote source at all, and only its detached .asc signature was.

    So: split on whitespace only when OUTSIDE quotes, and strip quote marks
    within a token rather than treating them as delimiters.
    """
    out, cur, q = [], [], None
    for c in body:
        if q:
            if c == q:
                q = None
            else:
                cur.append(c)
        elif c in "'\"":
            q = c
        elif c.isspace():
            if cur:
                out.append("".join(cur)); cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return out


def _scalar(text, name):
    m = re.search(r"^\s*%s\s*=\s*([^\s#]+)" % re.escape(name), text, re.M)
    return m.group(1).strip().strip('"').strip("'") if m else ""


def parse(text):
    """The parts of a PKGBUILD that describe where code comes from."""
    env = _assignments(text)
    srcs = []
    for raw in _array(text, "source"):
        e = _expand(raw, env)
        name, _, loc = e.rpartition("::") if "::" in e else ("", "", e)
        srcs.append({"raw": raw, "expanded": e, "rename": name, "loc": loc,
                     "remote": loc.startswith(REMOTE_SCHEMES),
                     "host": _host(loc),
                     "unresolved": "$" in loc})
    return {
        "sources": srcs,
        "sums": {k: _array(text, k) for k in
                 ("sha256sums", "sha512sums", "sha1sums", "md5sums", "b2sums")
                 if _array(text, k)},
        "validpgpkeys": _array(text, "validpgpkeys"),
        "install": _scalar(text, "install"),
        "noextract": _array(text, "noextract"),
    }


def _host(loc):
    m = re.match(r"[a-z+]+://(?:[^@/]*@)?([^/:]+)", loc)
    if m:
        return m.group(1)
    m = re.match(r"(?:git|svn|hg|bzr)\+[a-z]+://(?:[^@/]*@)?([^/:]+)", loc)
    return m.group(1) if m else ""


def diff(old_text, new_text):
    """Declaration-level changes between two PKGBUILD revisions.

    Ordered by how much a reviewer should care, most alarming first. Every
    finding names what it saw rather than scoring it, because the same change
    is routine in one package and the whole attack in another.
    """
    o, n = parse(old_text), parse(new_text)
    findings = []

    o_remote = [s for s in o["sources"] if s["remote"]]
    n_remote = [s for s in n["sources"] if s["remote"]]

    # THE HEADLINE CASE. A package that fetched nothing and now fetches.
    if not o_remote and n_remote:
        findings.append({
            "kind": "went_remote", "severity": "high",
            "detail": "the previous revision declared NO remote source; this one "
                      "fetches %d: %s" % (len(n_remote),
                                          ", ".join(s["loc"] for s in n_remote[:4])),
        })

    o_hosts = {s["host"] for s in o_remote if s["host"]}
    n_hosts = {s["host"] for s in n_remote if s["host"]}
    added = sorted(n_hosts - o_hosts)
    if added and o_remote:
        findings.append({
            "kind": "new_host", "severity": "high",
            "detail": "fetches from a host the previous revision did not: %s"
                      % ", ".join(added),
        })

    # SAME URL, DIFFERENT CHECKSUM. The upstream bytes changed under a name that
    # did not. Routine on a version bump; on an unchanged pkgver it is the
    # signature of a swapped tarball.
    # REMOTE ENTRIES ONLY. A local file's checksum changing is what a version
    # bump IS -- the .c file in the repo was edited. Measured on the real
    # pkgcacheclean history, including local files made this fire on two of the
    # three ordinary releases and call them "the bytes at an unchanged address
    # changed", which is true of a local file in the least alarming possible
    # way. A finding that fires on routine maintenance costs the reader the
    # attention the real one needs.
    o_map = {s["loc"]: c for s, c in
             zip(o["sources"], next(iter(o["sums"].values()), [])) if s["remote"]}
    n_map = {s["loc"]: c for s, c in
             zip(n["sources"], next(iter(n["sums"].values()), [])) if s["remote"]}
    swapped = [u for u in o_map if u in n_map
               and o_map[u] != n_map[u]
               and "SKIP" not in (o_map[u], n_map[u])]
    if swapped:
        findings.append({
            "kind": "checksum_changed_same_url", "severity": "high",
            "detail": "same URL, different checksum -- the bytes at an unchanged "
                      "address changed: %s" % ", ".join(swapped[:3]),
        })

    # Checksums turned off entirely.
    #
    # A DETACHED SIGNATURE DOES NOT GET A CHECKSUM, and counting it made this
    # fire on the same commit as the went_remote finding above -- doubling the
    # alarm on one event and, worse, teaching the reader that SKIP is normal
    # here. A .asc/.sig is verified by GPG against validpgpkeys, so SKIP is the
    # correct value for it and carries no information.
    def _skips(p):
        sig = tuple(".asc .sig .sign".split())
        locs = [s["loc"] for s in p["sources"]]
        n = 0
        for arr in p["sums"].values():
            for i, c in enumerate(arr):
                if c == "SKIP" and not (i < len(locs) and locs[i].endswith(sig)):
                    n += 1
        return n
    o_skip, n_skip = _skips(o), _skips(n)
    if n_skip > o_skip:
        findings.append({
            "kind": "integrity_skipped", "severity": "high",
            "detail": "%d more source(s) have their checksum set to SKIP than "
                      "before" % (n_skip - o_skip),
        })
    if o["sums"] and not n["sums"]:
        findings.append({"kind": "sums_removed", "severity": "high",
                         "detail": "the checksum arrays were removed entirely"})

    # An install scriptlet runs as root on the USER'S machine, at install time,
    # outside anything this sandbox observes. Gaining one is worth a line.
    if n["install"] and n["install"] != o["install"]:
        findings.append({
            "kind": "install_script", "severity": "high" if not o["install"] else "medium",
            "detail": ("gained an install scriptlet (%s), which runs as root at "
                       "install time" % n["install"]) if not o["install"]
                      else "install scriptlet changed: %s -> %s" % (o["install"], n["install"]),
        })

    if set(o["validpgpkeys"]) - set(n["validpgpkeys"]):
        findings.append({
            "kind": "pgpkey_removed", "severity": "medium",
            "detail": "a validpgpkeys entry was removed: %s"
                      % ", ".join(sorted(set(o["validpgpkeys"]) - set(n["validpgpkeys"]))),
        })
    if set(n["validpgpkeys"]) - set(o["validpgpkeys"]):
        findings.append({
            "kind": "pgpkey_added", "severity": "medium",
            "detail": "signing key changed to one the previous revision did not "
                      "trust: %s" % ", ".join(sorted(set(n["validpgpkeys"]) - set(o["validpgpkeys"]))),
        })

    # The reverse transition, reported because it is informative, not alarming.
    if o_remote and not n_remote:
        findings.append({"kind": "went_local", "severity": "info",
                         "detail": "no longer declares any remote source"})

    unresolved = [s["loc"] for s in n["sources"] if s["unresolved"]]
    if unresolved:
        findings.append({
            "kind": "unresolved", "severity": "info",
            "detail": "could not resolve to a host without running shell: %s"
                      % ", ".join(unresolved[:3]),
        })
    return findings


def summarise(findings):
    if not findings:
        return "declarations unchanged in every field this reads"
    order = {"high": 0, "medium": 1, "info": 2}
    return "\n".join("  [%-6s] %s" % (f["severity"], f["detail"])
                     for f in sorted(findings, key=lambda f: order[f["severity"]]))


# ---------------------------------------------------------------- self-test ---
if __name__ == "__main__":
    # The real transition 0e found, reduced to its declarations.
    OLD = '''
pkgname=pkgcacheclean
pkgver=1.9.0
source=($pkgname.c $pkgname.8)
sha256sums=('aaaa' 'bbbb')
'''
    NEW = '''
pkgname=pkgcacheclean
pkgver=1.9.0
source=("https://github.com/example/$pkgname/archive/v$pkgver.tar.gz")
sha256sums=('cccc')
'''
    f = diff(OLD, NEW)
    print("pkgcacheclean local -> remote:")
    print(summarise(f))
    kinds = {x["kind"] for x in f}
    assert "went_remote" in kinds, "the headline transition must be reported"

    # A version bump that only changes the checksum because the version moved is
    # NOT the same as a checksum changing under a URL that did not.
    B1 = '''
pkgname=p
pkgver=1.0
source=("https://h.example/p-$pkgver.tar.gz")
sha256sums=('1111')
'''
    B2 = B1.replace("pkgver=1.0", "pkgver=1.1").replace("1111", "2222")
    assert not [x for x in diff(B1, B2) if x["kind"] == "checksum_changed_same_url"], \
        "a version bump must not read as a swapped tarball"

    # ...but the same URL with different bytes must.
    C2 = B1.replace("1111", "2222")
    assert [x for x in diff(B1, C2) if x["kind"] == "checksum_changed_same_url"], \
        "same URL with a new checksum must be reported"

    # An arch-suffixed array is still a source array.
    A1 = 'pkgname=p\nsource=()\n'
    A2 = 'pkgname=p\nsource=()\nsource_x86_64=("https://evil.example/x.bin")\n'
    assert "went_remote" in {x["kind"] for x in diff(A1, A2)}, \
        "source_x86_64 must count as a source"

    # Gaining an install scriptlet runs root code outside anything we observe.
    I2 = B1 + "\ninstall=p.install\n"
    assert "install_script" in {x["kind"] for x in diff(B1, I2)}

    # Turning checksums off.
    S2 = B1.replace("'1111'", "'SKIP'")
    assert "integrity_skipped" in {x["kind"] for x in diff(B1, S2)}

    # Identical text must be silent -- the property that makes a finding mean
    # something. A checker that fires on everything is not a checker.
    assert diff(B1, B1) == [], "identical declarations must produce no findings"

    # REGRESSION, found only by running against the real AUR history and not by
    # any fixture written here: both halves of name::url separately quoted.
    Q = '''
pkgname=pkgcacheclean
pkgver=1.9.0
source=("${pkgname}-${pkgver}.tar.gz"::"https://github.com/d/pkgcacheclean/archive/v${pkgver}.tar.gz"
        "https://github.com/d/pkgcacheclean/releases/download/v${pkgver}/x.tar.gz.asc")
'''
    qs = parse(Q)["sources"]
    assert len(qs) == 2, "quoted name::url must be ONE entry, got %d" % len(qs)
    assert all(s["remote"] for s in qs), \
        "a quoted URL after :: must still read as remote: %r" % [s["loc"] for s in qs]
    assert qs[0]["rename"] == "pkgcacheclean-1.9.0.tar.gz"

    # REGRESSION: a LOCAL file's checksum changing is what a version bump is.
    L1 = "pkgname=p\npkgver=1.0\nsource=(p.c p.8)\nsha256sums=('aa' 'bb')\n"
    L2 = "pkgname=p\npkgver=1.1\nsource=(p.c p.8)\nsha256sums=('cc' 'bb')\n"
    assert not [x for x in diff(L1, L2) if x["kind"] == "checksum_changed_same_url"], \
        "a local file's checksum changing must not read as a swapped tarball"

    print("\nself-test: went_remote=OK  version-bump-not-a-swap=OK  swap=OK")
    print("           arch-array=OK  install=OK  SKIP=OK  identical-silent=OK")
    print("           quoted-name::url=OK  local-sum-change-ignored=OK")
