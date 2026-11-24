#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause

# Uploads a deployment bundle to the Maven Central Publisher Portal so that
# Central validates it, reports the result, and drops the deployment.  It
# never publishes: the upload is USER_MANAGED, which Central holds until a
# separate publish request, and this script makes none.  Use it with a
# bundle built at a placeholder version to learn, before a real release,
# whether the publishing token may deploy every namespace in the bundle.

set -euo pipefail

bundle=${1:?deployment bundle required}
api=${2:-https://central.sonatype.com/api/v1/publisher}
poll_seconds=${3:-10}
: "${SONATYPE_USERNAME:?SONATYPE_USERNAME required}"
: "${SONATYPE_PASSWORD:?SONATYPE_PASSWORD required}"
if [[ ! -f $bundle ]]; then
  echo "Deployment bundle $bundle does not exist" >&2
  exit 1
fi

auth_file=$(mktemp)
deployment=
finish() {
  rm -f "$auth_file"
  if [[ -n $deployment ]]; then
    echo "::warning::Deployment $deployment was not dropped; drop it at https://central.sonatype.com/publishing/deployments" >&2
  fi
}
trap finish EXIT
chmod 600 "$auth_file"
# Keep the token out of the process list.
printf 'header = "Authorization: Bearer %s"\n' \
  "$(printf '%s:%s' "$SONATYPE_USERNAME" "$SONATYPE_PASSWORD" | base64 | tr -d '\n')" > "$auth_file"
call() {
  curl --silent --show-error --fail-with-body --max-time 300 --config "$auth_file" "$@"
}

uploaded=$(call --request POST --form "bundle=@$bundle" \
  "$api/upload?name=validation-only&publishingType=USER_MANAGED")
if [[ ! $uploaded =~ ^[0-9a-f-]{36}$ ]]; then
  echo 'Central did not return a deployment identifier' >&2
  exit 1
fi
deployment=$uploaded
echo "Uploaded as deployment $deployment; waiting for validation"

state=PENDING
status=
for _ in $(seq 60); do
  status=$(call --request POST "$api/status?id=$deployment")
  state=$(jq -r '.deploymentState // "UNKNOWN"' <<<"$status")
  if [[ $state != PENDING && $state != VALIDATING ]]; then
    break
  fi
  sleep "$poll_seconds"
done
echo "Deployment state: $state"
jq '{deploymentState, purls, errors}' <<<"$status"

# Central drops only deployments that have finished validating.  One that
# is left behind stays unpublished, and the exit handler says so.
if [[ $state == VALIDATED || $state == FAILED ]] &&
    call --request DELETE "$api/deployment/$deployment" > /dev/null; then
  echo "Dropped deployment $deployment"
  deployment=
fi

if [[ $state != VALIDATED ]]; then
  echo 'Central did not validate the bundle' >&2
  exit 1
fi
echo 'Central validated the bundle; nothing was published'
