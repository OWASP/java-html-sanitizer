#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

# Runs a command, normally JReleaser, with the release key alone in a
# temporary GnuPG home, and points JReleaser's gpg command signer at it.

set -euo pipefail

if (($# == 0)); then
  echo 'Command required' >&2
  exit 1
fi
: "${GPG_SECRET_KEY:?GPG_SECRET_KEY required}"
: "${GPG_PUBLIC_KEY:?GPG_PUBLIC_KEY required}"
: "${EXPECTED_GPG_FINGERPRINT:?EXPECTED_GPG_FINGERPRINT required}"
if [[ ! $EXPECTED_GPG_FINGERPRINT =~ ^[0-9A-F]{40}$ ]]; then
  echo 'Invalid expected release signing fingerprint' >&2
  exit 1
fi

signing_home=$(mktemp -d)
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$signing_home"' EXIT
chmod 700 "$signing_home"
export GNUPGHOME=$signing_home
public_fingerprint=$(printf '%s\n' "$GPG_PUBLIC_KEY" |
  gpg --batch --show-keys --with-colons |
  awk -F: '$1 == "fpr" { print $10; exit }')
if [[ $public_fingerprint != "$EXPECTED_GPG_FINGERPRINT" ]]; then
  echo 'Release public key fingerprint does not match the configured key' >&2
  exit 1
fi
printf '%s\n' "$GPG_PUBLIC_KEY" | gpg --batch --quiet --import
printf '%s\n' "$GPG_SECRET_KEY" | gpg --batch --quiet --import

fingerprint=$(gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "sec" { primary = 1; next } $1 == "fpr" && primary { print $10; primary = 0 }')
if [[ $fingerprint != "$EXPECTED_GPG_FINGERPRINT" ]]; then
  echo 'Expected exactly one release signing key, the configured one' >&2
  exit 1
fi

export JRELEASER_GPG_HOMEDIR=$signing_home
export JRELEASER_GPG_KEYNAME=$fingerprint
"$@"
