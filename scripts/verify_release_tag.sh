#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'release tag verification failed: %s\n' "$*" >&2
  exit 1
}

validate_inputs() {
  local tag=$1 expected_tag_oid=$2 expected_commit=$3
  git check-ref-format "refs/tags/${tag}" >/dev/null 2>&1 || fail "invalid tag name: ${tag}"
  test -n "$expected_tag_oid" || fail "expected tag object OID is empty"
  test -n "$expected_commit" || fail "expected peeled commit is empty"
}

verify_local_tag() {
  local tag=$1 expected_tag_oid=$2 expected_commit=$3
  local tag_ref="refs/tags/${tag}" tag_oid peeled_commit checked_out_head

  validate_inputs "$tag" "$expected_tag_oid" "$expected_commit"
  tag_oid="$(git rev-parse --verify "$tag_ref")" || fail "missing local tag ref: ${tag_ref}"
  test "$tag_oid" = "$expected_tag_oid" || fail "local tag object OID changed: expected ${expected_tag_oid}, found ${tag_oid}"
  peeled_commit="$(git rev-parse --verify "${tag_ref}^{commit}")" || fail "local tag does not peel to a commit: ${tag_ref}"
  test "$peeled_commit" = "$expected_commit" || fail "local tag peeled commit changed: expected ${expected_commit}, found ${peeled_commit}"
  checked_out_head="$(git rev-parse --verify HEAD)" || fail "cannot resolve checked-out HEAD"
  test "$checked_out_head" = "$expected_commit" || fail "checked-out HEAD differs from release commit: expected ${expected_commit}, found ${checked_out_head}"
}

verify_remote_tag() {
  local remote=$1 tag=$2 expected_tag_oid=$3 expected_commit=$4
  local tag_ref="refs/tags/${tag}" remote_refs tag_oid="" peeled_oid="" oid ref remote_commit

  validate_inputs "$tag" "$expected_tag_oid" "$expected_commit"
  remote_refs="$(git ls-remote "$remote" "$tag_ref" "${tag_ref}^{}")" || fail "cannot query remote tag: ${remote} ${tag_ref}"
  while read -r oid ref; do
    test -n "${oid:-}" || continue
    case "$ref" in
      "$tag_ref")
        test -z "$tag_oid" || fail "duplicate remote direct tag ref: ${tag_ref}"
        tag_oid=$oid
        ;;
      "${tag_ref}^{}")
        test -z "$peeled_oid" || fail "duplicate remote peeled tag ref: ${tag_ref}^{}"
        peeled_oid=$oid
        ;;
      *)
        fail "unexpected remote ref: ${ref}"
        ;;
    esac
  done <<< "$remote_refs"

  test -n "$tag_oid" || fail "missing remote direct tag ref: ${tag_ref}"
  test "$tag_oid" = "$expected_tag_oid" || fail "remote tag object OID changed: expected ${expected_tag_oid}, found ${tag_oid}"
  remote_commit=${peeled_oid:-$tag_oid}
  test "$remote_commit" = "$expected_commit" || fail "remote tag peeled commit changed: expected ${expected_commit}, found ${remote_commit}"
}

case "${1:-}" in
  local)
    test "$#" -eq 4 || fail "usage: $0 local TAG EXPECTED_TAG_OID EXPECTED_COMMIT"
    verify_local_tag "$2" "$3" "$4"
    ;;
  remote)
    test "$#" -eq 5 || fail "usage: $0 remote REMOTE TAG EXPECTED_TAG_OID EXPECTED_COMMIT"
    verify_remote_tag "$2" "$3" "$4" "$5"
    ;;
  *)
    fail "usage: $0 {local TAG EXPECTED_TAG_OID EXPECTED_COMMIT|remote REMOTE TAG EXPECTED_TAG_OID EXPECTED_COMMIT}"
    ;;
esac
