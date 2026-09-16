#!/usr/bin/env bash
# Fail if the README claims something the repo does not have.
#
# This exists because the README once documented --anonymise while the shipped
# source defined no such flag: it was added to a working copy, the screenshots
# were regenerated from that copy, and only the images were committed. Viewing
# the screenshots confirmed they were clean -- a fact about the screenshots, not
# about whether the mechanism shipped.
#
# Note on flag extraction. The first version of this script flagged every --foo
# anywhere in the README, and immediately produced a false positive on
# --unshare-net: a bubblewrap flag discussed in prose, not one this tool accepts.
# A checker that cannot tell "a flag we define" from "a flag we mention" measures
# the wrong thing -- the same defect it was written to catch. So a flag counts as
# CLAIMED only where the README shows it passed to a command this repo ships.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
fail=0

# EVERY flag in the README counts, minus an explicit exemption list. Narrowing
# this to flags shown beside one of our binaries was tried and silently stopped
# catching the very bug this was written for: the flag was documented in prose,
# not in a usage block. Fail closed -- a new external flag must be declared.
exempt=tools/external-flags.txt
claimed=$(grep -oE -- '(^|[^-])--[a-z][a-z0-9-]+' README.md 2>/dev/null \
          | grep -oE -- '--[a-z][a-z0-9-]+' | sort -u)
for f in $claimed; do
  grep -rqF -- "\"$f\"" src/ bin/ 2>/dev/null && continue
  grep -rqF -- "$f" bin/ 2>/dev/null && continue
  grep -qE "^\\s*$f(\\s|$)" "$exempt" 2>/dev/null && continue
  echo "README documents $f, nothing defines it, and it is not declared in $exempt" >&2
  fail=1
done

for p in $(grep -oE '`(src|bin|docs|tools|config)/[A-Za-z0-9_.-]+`' README.md 2>/dev/null | tr -d '`' | sort -u); do
  [ -e "$p" ] || { echo "README references $p, which does not exist" >&2; fail=1; }
done
for i in $(grep -oE '!\[[^]]*\]\(([^)]+)\)' README.md 2>/dev/null | sed 's/.*(\(.*\))/\1/'); do
  case "$i" in http*) continue;; esac
  [ -f "$i" ] || { echo "README embeds $i, which does not exist" >&2; fail=1; }
done
if grep -qi '\bMIT\b' README.md && [ ! -f LICENSE ]; then
  echo "README claims MIT, no LICENSE file" >&2; fail=1
fi
for p in src/*.py; do [ -f "$p" ] || continue
  python3 -c "import ast;ast.parse(open('$p').read())" 2>/dev/null \
    || { echo "$p does not parse" >&2; fail=1; }
done
for s in bin/* tools/* install.sh; do [ -f "$s" ] || continue
  head -1 "$s" | grep -q bash || continue
  bash -n "$s" 2>/dev/null || { echo "$s does not parse" >&2; fail=1; }
done

((fail)) && { echo "FAIL: the README claims something this repo does not have" >&2; exit 1; }
echo "ok: README claims check out ($(echo "$claimed" | wc -w) flags, all referenced paths and images)"
