#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

set -euo pipefail

tag=${1:?release tag required}
commit=${2:?release commit required}
mode=${3:-create}

if [[ ! $tag =~ ^release-[0-9]{8}\.[0-9]+$ || ! $commit =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Invalid release tag or commit' >&2
  exit 1
fi
if [[ $mode != create && $mode != repair ]]; then
  echo 'Mode must be create or repair' >&2
  exit 1
fi
: "${GPG_SECRET_KEY:?GPG_SECRET_KEY required}"
: "${GPG_PUBLIC_KEY:?GPG_PUBLIC_KEY required}"
: "${GPG_PASSPHRASE:?GPG_PASSPHRASE required}"

remote_ref=$(git ls-remote --refs origin "refs/tags/$tag")
if [[ $mode == create ]]; then
  if [[ -n $remote_ref ]] || git show-ref --verify --quiet "refs/tags/$tag"; then
    echo "Tag $tag already exists" >&2
    exit 1
  fi
else
  if [[ $remote_ref != "$commit"$'\t'"refs/tags/$tag" ]]; then
    echo "Remote tag $tag has changed or is not a lightweight tag at $commit" >&2
    exit 1
  fi
  if [[ $(git rev-parse "refs/tags/$tag^{commit}") != "$commit" ||
        $(git cat-file -t "refs/tags/$tag") != commit ]]; then
    echo "Local tag $tag is not a lightweight tag at $commit" >&2
    exit 1
  fi
fi

signing_home=$(mktemp -d)
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$signing_home"' EXIT
chmod 700 "$signing_home"
export GNUPGHOME=$signing_home
printf '%s\n' "$GPG_PUBLIC_KEY" | gpg --batch --quiet --import
printf '%s\n' "$GPG_SECRET_KEY" | gpg --batch --quiet --import

fingerprint=$(gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "sec" { primary = 1; next } $1 == "fpr" && primary { print $10; primary = 0 }')
if [[ ! $fingerprint =~ ^[0-9A-F]{40}$ ]]; then
  echo 'Expected exactly one release signing key' >&2
  exit 1
fi
uid=$(gpg --batch --with-colons --list-secret-keys |
  awk -F: '$1 == "uid" { print $10; exit }')
if [[ ! $uid =~ ^(.+)\ \<([^\<\>]+)\>$ ]]; then
  echo 'Release signing key needs a name and email address' >&2
  exit 1
fi
tagger_name=${BASH_REMATCH[1]}
tagger_email=${BASH_REMATCH[2]}

cat > "$signing_home/gpg-for-git" <<'EOF'
#!/usr/bin/env bash
exec gpg --batch --pinentry-mode loopback --passphrase-fd 3 "$@" 3<<<"$GPG_PASSPHRASE"
EOF
chmod 700 "$signing_home/gpg-for-git"

if [[ $mode == repair ]]; then
  git tag -d "$tag"
fi
GIT_COMMITTER_NAME=$tagger_name GIT_COMMITTER_EMAIL=$tagger_email \
  git -c "gpg.program=$signing_home/gpg-for-git" tag -s -u "$fingerprint" \
  -m "Release ${tag#release-}" "$tag" "$commit"
git tag -v "$tag"
if [[ $(git rev-parse "$tag^{commit}") != "$commit" ]]; then
  echo 'Signed tag does not point to the expected commit' >&2
  exit 1
fi

if [[ $mode == repair ]]; then
  git push --force-with-lease="refs/tags/$tag:$commit" origin "refs/tags/$tag"
else
  git push origin "refs/tags/$tag"
fi
