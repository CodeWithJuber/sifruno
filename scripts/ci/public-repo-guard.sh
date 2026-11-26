#!/usr/bin/env bash
# Fails when a workflow could run untrusted code on a machine that is not
# GitHub's, or hand a pull request's code a token or secrets. Sifruno is a
# public repository: anyone can open a pull request, and every job of a
# pull_request run executes that pull request's code. A line that breaks a
# rule is printed as FILE:LINE: why. CI runs it first, and so does
# `npm run check:workflows`.
#
#   bash scripts/ci/public-repo-guard.sh [FILE...]
#   (default: every YAML file under .github/workflows)
#
# The rules:
#   - runs-on names GitHub-hosted standard runners (ubuntu-24.04 and the like)
#     literally. A self-hosted runner would run a stranger's code on our own
#     machine, an expression, a variable or a runner group could pick one, and
#     larger runners are billed by the minute.
#   - No reusable workflow from another repository: its jobs pick their own
#     runners, out of this check's sight.
#   - Every action is pinned to a full 40-character commit SHA. A tag can be
#     moved to other code. Local ./ actions and docker:// images are exempt.
#   - Every workflow sets top-level permissions, so no job gets the default
#     write token by accident.
#   - Every actions/checkout sets persist-credentials: false, so the job token
#     is not left in .git/config for the steps that follow.
#   - A workflow triggered by pull_request_target runs with secrets and a write
#     token, so it never checks out or fetches the pull request's code: no
#     checkout with ref or repository, and no use of the pull request's head,
#     refs/pull/ or gh pr checkout.
set -euo pipefail

files=()
if (($#)); then
  files=("$@")
else
  cd "$(dirname "${BASH_SOURCE[0]}")/../.."
  while IFS= read -r -d '' file; do files+=("$file"); done \
    < <(git ls-files -z -- '.github/workflows/*.yml' '.github/workflows/*.yaml')
fi
((${#files[@]})) || exit 0

# POSIX awk, so it runs the same with mawk, gawk and the BSD awk on macOS.
program=$(
  cat <<'AWK'
function report(line, why) { printf "%s:%d: %s\n", file, line, why; failed = 1 }
function indent_of(text) { match(text, /^ */); return RLENGTH }
function value_of(text) {
  sub(/^[^:]*:[ \t]*/, "", text)
  gsub(/^["']|["']$/, "", text)
  return text
}
function hosted(label) {
  return label ~ /^(ubuntu-latest|ubuntu-24\.04|ubuntu-22\.04|ubuntu-24\.04-arm|ubuntu-22\.04-arm|windows-latest|windows-2025|windows-2022|macos-latest|macos-15|macos-14)$/
}
function check_labels(text, line,    n, i, parts, label, seen) {
  gsub(/[][]/, " ", text)
  n = split(text, parts, /[ ,]+/)
  seen = 0
  for (i = 1; i <= n; i++) {
    label = parts[i]
    gsub(/^["']|["']$/, "", label)
    if (label == "") continue
    seen = 1
    if (label == "self-hosted")
      report(line, "runs-on must name a GitHub-hosted runner such as ubuntu-24.04. A self-hosted runner would run code from any pull request on that machine.")
    else if (!hosted(label))
      report(line, "runs-on label \"" label "\" is not a GitHub-hosted standard runner. Use ubuntu-24.04; larger runners are billed and custom labels can reach self-hosted ones.")
  }
  if (!seen) report(line, "runs-on names no runner. Use ubuntu-24.04.")
}
function finish_runs_on() {
  if (!pending) return
  pending = 0
  if (!grouped) check_labels(labels, runs_on_line)
}
function finish_checkout() {
  if (!checkout) return
  checkout = 0
  if (!checkout_persist)
    report(checkout_line, "actions/checkout needs persist-credentials: false, so the job token is not left in .git/config for later steps.")
  if (checkout_ref) target_lines = target_lines " " checkout_ref
}
function finish_file(    n, i, parts, done) {
  finish_runs_on()
  finish_checkout()
  if (file == "") return
  if (!permissions)
    report(1, "Set top-level permissions (for example contents: read), so no job gets a write token by default.")
  if (pr_target && target_lines != "") {
    n = split(target_lines, parts, " ")
    done = " "
    for (i = 1; i <= n; i++)
      if (parts[i] != "" && index(done, " " parts[i] " ") == 0) {
        done = done parts[i] " "
        report(parts[i] + 0, "This workflow runs on pull_request_target, with secrets and a write token. It must not check out or fetch the pull request's code.")
      }
  }
}
FNR == 1 {
  finish_file()
  file = FILENAME
  pending = 0; grouped = 0; labels = ""
  checkout = 0; checkout_ref = ""; target_lines = ""
  permissions = 0; pr_target = 0; in_on = 0; item_indent = 0
}
/^[ \t]*#/ { next }
/^[ \t]*$/ { next }
{ line = $0; sub(/[ \t]+#.*$/, "", line); indent = indent_of(line) }
pending {
  if (indent > runs_on_indent || (indent == runs_on_indent && line ~ /^[ \t]*-[ \t]/)) {
    if (line ~ /^[ \t]*group:/) {
      grouped = 1
      report(FNR, "runs-on must not name a runner group: a group can hold self-hosted or larger runners.")
    } else if (line ~ /^[ \t]*labels:/) {
      labels = labels " " value_of(line)
    } else if (line ~ /^[ \t]*-[ \t]/) {
      item = line; sub(/^[ \t]*-[ \t]*/, "", item); labels = labels " " item
    }
    if (line ~ /\$\{\{/) report(FNR, "runs-on must name its runner literally. An expression or a variable could pick a self-hosted runner.")
    next
  }
  finish_runs_on()
}
checkout && indent <= checkout_indent { finish_checkout() }
checkout {
  if (line ~ /^[ \t]*persist-credentials:[ \t]*["']?false["']?[ \t]*$/) checkout_persist = 1
  if (line ~ /^[ \t]*(ref|repository):/) checkout_ref = checkout_ref " " FNR
}
indent == 0 {
  in_on = (line ~ /^["']?on["']?:/)
  if (line ~ /^permissions:/) permissions = 1
}
in_on && line ~ /(^|[^A-Za-z_])pull_request_target([^A-Za-z_]|$)/ { pr_target = 1 }
line ~ /github\.event\.pull_request\.head\.|github\.head_ref|refs\/pull\/|gh[ \t]+pr[ \t]+checkout/ {
  target_lines = target_lines " " FNR
}
line ~ /^[ \t]*-[ \t]/ { item_indent = indent }
line ~ /^[ \t]*(-[ \t]+)?runs-on:/ {
  value = value_of(line)
  if (value ~ /\$\{\{/)
    report(FNR, "runs-on must name its runner literally. An expression or a variable could pick a self-hosted runner.")
  else if (value == "") { pending = 1; grouped = 0; labels = ""; runs_on_line = FNR; runs_on_indent = indent }
  else check_labels(value, FNR)
}
line ~ /^[ \t]*(-[ \t]+)?uses:/ {
  target = value_of(line)
  if (target ~ /^\.\// || target ~ /^docker:\/\//) next
  if (target ~ /\.github\/workflows\//) {
    report(FNR, "A reusable workflow from another repository picks its own runners. Copy its steps here instead.")
    next
  }
  at = index(target, "@")
  ref = at ? substr(target, at + 1) : ""
  if (!(ref ~ /^[0-9a-f]+$/ && length(ref) == 40))
    report(FNR, "Pin " target " to a full commit SHA, with the version in a comment. A tag can be moved to other code.")
  if (target ~ /^actions\/checkout@/) {
    checkout = 1; checkout_line = FNR; checkout_indent = item_indent
    checkout_persist = 0; checkout_ref = ""
  }
}
END { finish_file(); exit failed }
AWK
)

if ! awk "$program" "${files[@]}"; then
  echo 'A workflow above breaks a rule for public repositories (see the top of scripts/ci/public-repo-guard.sh).' >&2
  exit 1
fi
