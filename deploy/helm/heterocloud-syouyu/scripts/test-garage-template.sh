#!/usr/bin/env bash
set -Eeuo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

helm template syouyu "$chart_dir" \
  --namespace heterocloud-syouyu \
  --include-crds \
  -f "$chart_dir/ci/test-values.yaml" >"$rendered"

grep -q '^kind: StatefulSet$' "$rendered"
grep -q '^  replicas: 3$' "$rendered"
grep -q 'image: "dxflrs/garage:v2.3.0"' "$rendered"
grep -A1 'name: GARAGE_ALLOW_WORLD_READABLE_SECRETS' "$rendered" | grep -q 'value: "true"'
grep -q 'replication_factor = 3' "$rendered"
grep -q 'consistency_mode = "consistent"' "$rendered"
grep -q 'requiredDuringSchedulingIgnoredDuringExecution:' "$rendered"

claim_count="$(grep -c 'accessModes: \["ReadWriteOnce"\]' "$rendered")"
if [[ "$claim_count" -ne 2 ]]; then
  echo "expected exactly two per-pod RWO volume claim templates, got $claim_count" >&2
  exit 1
fi

grep -q 'name: meta$' "$rendered"
grep -q 'name: data$' "$rendered"
grep -q 'minAvailable: 2' "$rendered"

# Synthetic test digest only; no image is pulled or deployed.
digest="sha256:$(printf 'a%.0s' {1..64})"
helm template syouyu "$chart_dir" \
  --namespace heterocloud-syouyu \
  -f "$chart_dir/ci/test-values.yaml" \
  --set-string "garage.image.digest=$digest" >"$rendered"
grep -Fq "image: \"dxflrs/garage@$digest\"" "$rendered"

for invalid in sha256:abc sha512:abcd latest; do
  if helm template syouyu "$chart_dir" \
    -f "$chart_dir/ci/test-values.yaml" \
    --set-string "garage.image.digest=$invalid" >"$rendered" 2>&1; then
    echo "invalid Garage image digest was accepted" >&2
    exit 1
  fi
  grep -q 'garage.image.digest' "$rendered"
done

if helm template syouyu "$chart_dir" \
  -f "$chart_dir/ci/test-values.yaml" \
  --set-string garage.image.tag=v9.9.9 \
  --set-string "garage.image.digest=$digest" >"$rendered" 2>&1; then
  echo "unsupported Garage version was accepted" >&2
  exit 1
fi
grep -q 'garage.image.tag' "$rendered"
