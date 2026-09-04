#!/usr/bin/env bash
set -Eeuo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

helm template syouyu "$chart_dir" \
  --namespace heterocloud-syouyu \
  -f "$chart_dir/ci/test-values.yaml" >"$rendered"

grep -q '^kind: Job$' "$rendered"
grep -q 'argocd.argoproj.io/hook: Sync' "$rendered"
grep -q 'argocd.argoproj.io/hook-delete-policy: BeforeHookCreation,HookSucceeded' "$rendered"
if grep -q 'helm.sh/hook: post-install' "$rendered"; then
  echo 'layout bootstrap must run during Argo CD Sync, not PostSync' >&2
  exit 1
fi
grep -q '/v2/GetClusterStatus' "$rendered"
grep -q '/v2/UpdateClusterLayout' "$rendered"
grep -q '/v2/ApplyClusterLayout' "$rendered"
grep -q 'layout already matches the requested three-node layout' "$rendered"
grep -q 'statefulset.kubernetes.io/pod-name: syouyu-heterocloud-syouyu-garage-0' "$rendered"
grep -q 'storage-a' "$rendered"
grep -q 'storage-b' "$rendered"
grep -q 'storage-c' "$rendered"
