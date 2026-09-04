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
