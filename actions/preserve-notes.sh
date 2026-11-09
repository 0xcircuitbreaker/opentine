#!/bin/sh
# Carry refs/notes/tine across a squash or rebase merge (actions/preserve-notes).
#
# Environment: BASE, HEAD, MERGED (commit ids), PR (number, optional),
# NOTES_REF (default refs/notes/tine), PUSH ("true" to push), REMOTE (origin),
# PYTHON (python). Runs in the checkout. Exit 0 also when there is nothing to carry.
set -euf

PYTHON=${PYTHON:-python}
REMOTE=${REMOTE:-origin}
NOTES_REF=${NOTES_REF:-refs/notes/tine}
case "$NOTES_REF" in
  refs/notes/*) ;;
  *) echo "notes ref must be under refs/notes/" >&2; exit 2 ;;
esac

fetch_notes() {
  git fetch --quiet "$REMOTE" "+$NOTES_REF:$NOTES_REF" 2>/dev/null || true
}

fetch_notes
if ! git cat-file -e "$HEAD^{commit}" 2>/dev/null && [ -n "${PR:-}" ]; then
  git fetch --quiet "$REMOTE" "+refs/pull/$PR/head:refs/opentine/pr-head" || true
fi

attempt=1
while :; do
  result=$($PYTHON -m opentine._ci_notes --base "$BASE" --head "$HEAD" --merged "$MERGED" --ref "$NOTES_REF")
  if [ "${PUSH:-true}" != "true" ] || git push --quiet "$REMOTE" "$NOTES_REF:$NOTES_REF"; then
    break
  fi
  # Someone else moved the notes ref: take theirs and carry again.
  [ "$attempt" -lt 3 ] || { echo "pushing $NOTES_REF failed 3 times" >&2; exit 1; }
  attempt=$((attempt + 1))
  fetch_notes
done

printf '%s\n' "$result"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "result<<OPENTINE_EOF"
    printf '%s\n' "$result"
    echo "OPENTINE_EOF"
  } >> "$GITHUB_OUTPUT"
fi
