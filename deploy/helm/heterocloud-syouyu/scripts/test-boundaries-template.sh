#!/usr/bin/env bash
set -Eeuo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
external_secret_rendered="$(mktemp)"
trap 'rm -f "$rendered" "$external_secret_rendered"' EXIT

helm template syouyu "$chart_dir" \
  --namespace heterocloud-syouyu \
  -f "$chart_dir/ci/test-values.yaml" >"$rendered"

grep -q '^kind: HTTPRoute$' "$rendered"
grep -q 'name: syouyu-heterocloud-syouyu-s3' "$rendered"
grep -q 'name: syouyu-heterocloud-syouyu-garage-admin' "$rendered"
grep -q 'name: syouyu-heterocloud-syouyu-garage-admin-bootstrap' "$rendered"
grep -q '^kind: ServiceMonitor$' "$rendered"
grep -q 'authorization:' "$rendered"
grep -A1 'name: SYOUYU_MAX_TOTAL_CREDENTIALS' "$rendered" | grep -q 'value: "1000000"'
if grep -q '1e+06' "$rendered"; then
  echo "credential limits must render as decimal integers" >&2
  exit 1
fi

if grep -Eq '^  type: (LoadBalancer|NodePort)$' "$rendered"; then
  echo "Syouyu management and Garage admin must not be externally exposed" >&2
  exit 1
fi

policy_count="$(grep -c '^kind: NetworkPolicy$' "$rendered")"
if [[ "$policy_count" -lt 5 ]]; then
  echo "expected default-deny and component NetworkPolicies" >&2
  exit 1
fi

helm template syouyu "$chart_dir" \
  --namespace heterocloud-syouyu \
  --set secrets.create=false \
  --set secrets.existingSecret=externally-managed \
  --set garage.gateway.enabled=false >"$external_secret_rendered"

if grep -q '^kind: Secret$' "$external_secret_rendered"; then
  echo "chart rendered a Secret while external secret mode was selected" >&2
  exit 1
fi
grep -q 'secretName: externally-managed' "$external_secret_rendered"
