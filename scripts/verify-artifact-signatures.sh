#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

# Checks that every artifact in a Maven staging repository has a detached
# signature made by the configured release key.

set -euo pipefail

repository=${1:?staging repository required}
: "${GPG_PUBLIC_KEY:?GPG_PUBLIC_KEY required}"
: "${EXPECTED_GPG_FINGERPRINT:?EXPECTED_GPG_FINGERPRINT required}"
if [[ ! $EXPECTED_GPG_FINGERPRINT =~ ^[0-9A-F]{40}$ ]]; then
  echo 'Invalid expected release signing fingerprint' >&2
  exit 1
fi
if [[ ! -d $repository ]]; then
  echo "Staging repository $repository does not exist" >&2
  exit 1
fi

verify_home=$(mktemp -d)
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$verify_home"' EXIT
chmod 700 "$verify_home"
export GNUPGHOME=$verify_home
public_fingerprint=$(printf '%s\n' "$GPG_PUBLIC_KEY" |
  gpg --batch --show-keys --with-colons |
  awk -F: '$1 == "fpr" { print $10; exit }')
if [[ $public_fingerprint != "$EXPECTED_GPG_FINGERPRINT" ]]; then
  echo 'Release public key fingerprint does not match the configured key' >&2
  exit 1
fi
printf '%s\n' "$GPG_PUBLIC_KEY" | gpg --batch --quiet --import

checked=0
while IFS= read -r -d '' artifact; do
  case $artifact in
    *.asc | *.md5 | *.sha1 | *.sha256 | *.sha512 | */maven-metadata*) continue ;;
  esac
  if [[ ! -f $artifact.asc ]]; then
    echo "Missing signature for ${artifact#"$repository"/}" >&2
    exit 1
  fi
  status=$(gpg --batch --status-fd 1 --verify "$artifact.asc" "$artifact" 2>/dev/null) || true
  # VALIDSIG ends with the primary key fingerprint; its eighth field is the
  # hash algorithm, which must be SHA-256 (8), SHA-384 (9) or SHA-512 (10).
  read -r signer digest < <(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $NF, $10; exit }' <<<"$status") || true
  if [[ ${signer:-} != "$EXPECTED_GPG_FINGERPRINT" || ! ${digest:-} =~ ^(8|9|10)$ ]]; then
    echo "Bad, weak or unexpected signature on ${artifact#"$repository"/}:" >&2
    grep '^\[GNUPG:\] \(VALIDSIG\|BADSIG\|ERRSIG\|FAILURE\|NO_PUBKEY\|ERROR\)' <<<"$status" >&2 || true
    exit 1
  fi
  echo "Verified ${artifact#"$repository"/}"
  checked=$((checked + 1))
done < <(find "$repository" -type f -print0 | sort -z)

if ((checked == 0)); then
  echo "No artifacts found in $repository" >&2
  exit 1
fi
echo "$checked artifacts are signed by $EXPECTED_GPG_FINGERPRINT"
