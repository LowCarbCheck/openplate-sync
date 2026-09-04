#!/usr/bin/env sh
# The README's `## Documentation` table and the `docs/` directory must agree.
#
# openplate.de publishes these guides, and it publishes exactly the rows of that
# table: `openplate-website/scripts/sync-docs.ts` reads the table as the
# manifest and names no page itself. So the table is the contract, and a broken
# one is only visible after a release, in another repository, in a workflow no
# one is watching. This check moves that failure left, to the push that breaks
# it. M193 spec 05, decision 8.
#
# THREE RULES, and each one is a real failure the site would otherwise hit:
#
#   * a row pointing at a file that is not here — the site fails its sync and
#     keeps quoting the previous release,
#   * a `docs/*.md` no row mentions — a guide written and then published
#     nowhere, which is how a guide silently stays unread,
#   * a file with no `# ` heading — the site takes the page title from it and
#     has nothing to fall back on.
#
# NO NETWORK, NO NODE, NO DEPENDENCY. It is POSIX shell reading two files on
# this disk so it can be the first tier of the push gate, in front of the
# install-dependent ones, and still cost nothing.
#
# NOT CHECKED HERE: `docs/README.md` (a hub for GitHub's directory listing, not
# a guide) and `docs/adr/` (records, deliberately unpublished — decision 4).
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

fail() {
  echo "✖ docs manifest: $1" >&2
  exit 1
}

[ -f README.md ] || fail "there is no README.md to read the table from."

# The section, from its heading to the next `## ` heading.
section=$(awk '/^## Documentation[[:space:]]*$/ {inside = 1; next} /^## / {inside = 0} inside' README.md)
[ -n "$section" ] || fail "README.md has no '## Documentation' section — nothing says which docs exist."

# `| [**Title**](./path.md) | blurb |`, the row shape the site parses. The
# header row and the `| --- |` rule do not match, which is correct.
rows=$(printf '%s\n' "$section" | sed -n 's|^\| *\[\*\*[^]]*\*\*\](\./\([A-Za-z0-9_./-]*\.md\)) *\|.*\|$|\1|p')
[ -n "$rows" ] || fail "the Documentation table matched no rows — its shape has changed."

status=0

# A row without a file, and a file without a title.
for file in $rows; do
  if [ ! -f "$file" ]; then
    echo "✖ docs manifest: the table points at $file, which does not exist." >&2
    status=1
    continue
  fi
  if ! grep -q '^# ' "$file"; then
    echo "✖ docs manifest: $file has no '# ' title — the site would have no page heading." >&2
    status=1
  fi
done

# A file without a row. Only the top level of `docs/`, so `docs/adr/` is out by
# construction; `docs/README.md` is named out.
for file in docs/*.md; do
  [ -f "$file" ] || continue
  [ "$file" = "docs/README.md" ] && continue
  if ! printf '%s\n' "$rows" | grep -Fxq "$file"; then
    echo "✖ docs manifest: $file is in docs/ but no table row mentions it — nothing publishes it." >&2
    status=1
  fi
done

[ "$status" -eq 0 ] || {
  echo "  Fix the README table or the file, then push again. openplate.de reads this table." >&2
  exit 1
}

echo "  the README table and docs/ agree ($(printf '%s\n' "$rows" | wc -l | tr -d ' ') rows)"
