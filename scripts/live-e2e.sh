#!/usr/bin/env bash
set -Eeuo pipefail

readonly KUBECONFIG="${KUBECONFIG:-/etc/kubernetes/admin.conf}"
readonly KUBE_SERVER="${KUBE_SERVER:-}"
readonly SYOUYU_NAMESPACE="${SYOUYU_NAMESPACE:-heterocloud-syouyu}"
readonly HETEROCLOUD_NAMESPACE="${HETEROCLOUD_NAMESPACE:-heterocloud}"
readonly API_SERVICE="${SYOUYU_API_SERVICE:-heterocloud-syouyu-api}"
readonly S3_SERVICE="${SYOUYU_S3_SERVICE:-heterocloud-syouyu-s3}"
readonly GARAGE_STATEFULSET="${SYOUYU_GARAGE_STATEFULSET:-heterocloud-syouyu-garage}"
readonly PROVIDER_SECRET="${HETEROCLOUD_PROVIDER_SECRET:-heterocloud-provider-signing}"
readonly PRINCIPAL_SECRET="${HETEROCLOUD_SYOUYU_SECRET:-heterocloud-syouyu-access}"
readonly PROVIDER_KEY_ID="${HETEROCLOUD_PROVIDER_KEY_ID:-heterocloud-provider-1}"
readonly S3_ENDPOINT="${SYOUYU_S3_ENDPOINT:-https://s3.heterocloud.mizuame.app}"
readonly STORAGE_REGION="${SYOUYU_STORAGE_REGION:-heteronet-global}"
readonly PUBLIC_IPS="${SYOUYU_PUBLIC_IPS:-}"

workdir="$(mktemp -d /tmp/syouyu-live-e2e.XXXXXX)"
chmod 0700 "${workdir}"
umask 077

service_id="$(cat /proc/sys/kernel/random/uuid)"
organization_id="$(cat /proc/sys/kernel/random/uuid)"
project_id="$(cat /proc/sys/kernel/random/uuid)"
principal_id="$(cat /proc/sys/kernel/random/uuid)"
bucket_name="syouyu-e2e-${service_id%%-*}"
object_key="e2e/${service_id}.txt"
service_created=false
credential_created=false
object_created=false
garage_isolation_armed=false
garage_recovery_needed=false
garage_pod="${GARAGE_STATEFULSET}-2"

log() {
  printf '[syouyu-e2e] %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

kube() {
  local attempt
  local -a kubectl_args=(--kubeconfig "${KUBECONFIG}")
  if [[ -n ${KUBE_SERVER} ]]; then
    kubectl_args+=(--server "${KUBE_SERVER}")
  fi
  for attempt in $(seq 1 10); do
    if kubectl "${kubectl_args[@]}" --request-timeout=30s "$@"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

kube_to_file() {
  local output attempt temporary
  local -a kubectl_args=(--kubeconfig "${KUBECONFIG}")
  output=$1
  temporary="${output}.tmp"
  shift
  if [[ -n ${KUBE_SERVER} ]]; then
    kubectl_args+=(--server "${KUBE_SERVER}")
  fi
  for attempt in $(seq 1 10); do
    if kubectl "${kubectl_args[@]}" --request-timeout=30s \
      "$@" >"${temporary}"; then
      mv "${temporary}" "${output}"
      return 0
    fi
    sleep 2
  done
  rm -f "${temporary}"
  return 1
}

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

new_uuid() {
  cat /proc/sys/kernel/random/uuid
}

resolve_public_ips() {
  local ip record_type remainder
  local -A seen=()

  if [[ -n ${PUBLIC_IPS} ]]; then
    for ip in ${PUBLIC_IPS}; do
      if [[ -z ${seen[${ip}]+present} ]]; then
        seen["${ip}"]=true
        printf '%s\n' "${ip}"
      fi
    done
    return
  fi

  while read -r ip record_type remainder; do
    if [[ ${record_type} == STREAM && -z ${seen[${ip}]+present} ]]; then
      seen["${ip}"]=true
      printf '%s\n' "${ip}"
    fi
  done < <(getent ahostsv4 "${s3_host}")
}

require_status() {
  local actual=$1 expected=$2 operation=$3
  [[ " ${expected} " == *" ${actual} "* ]] \
    || fail "${operation} returned HTTP ${actual}; expected ${expected}"
}

provider_token() {
  local action=$1 jwt_id=$2 generation=${3:-1} now header claims signing_input signature
  now="$(date +%s)"
  header="$(jq -cn --arg kid "${PROVIDER_KEY_ID}" \
    '{alg:"EdDSA",typ:"JWT",kid:$kid}')"
  claims="$(jq -cn \
    --arg sub "${principal_id}" \
    --arg organization_id "${organization_id}" \
    --arg project_id "${project_id}" \
    --arg service_instance_id "${service_id}" \
    --arg action "${action}" \
    --arg jti "${jwt_id}" \
    --argjson generation "${generation}" \
    --argjson iat "${now}" \
    '{iss:"heterocloud",aud:"heterocloud-syouyu",sub:$sub,
      organization_id:$organization_id,project_id:$project_id,
      service_instance_id:$service_instance_id,action:$action,generation:$generation,
      jti:$jti,iat:$iat,nbf:($iat-5),exp:($iat+60)}')"
  signing_input="$(printf '%s' "${header}" | base64url).$(printf '%s' "${claims}" | base64url)"
  printf '%s' "${signing_input}" >"${workdir}/provider-signing-input"
  signature="$(openssl pkeyutl -sign -rawin \
    -inkey "${workdir}/provider-private.pem" \
    -in "${workdir}/provider-signing-input" | base64url)"
  printf '%s.%s' "${signing_input}" "${signature}"
}

sign_principal() {
  local now principal hmac_key
  now="$(date +%s)"
  principal="$(jq -cn \
    --arg organization_id "${organization_id}" \
    --arg project_id "${project_id}" \
    --arg service_instance_id "${service_id}" \
    --arg principal_id "${principal_id}" \
    --arg context_id "$(new_uuid)" \
    --argjson iat "${now}" \
    '{issuer:"heterocloud",audience:"heterocloud-syouyu-data",
      organization_id:$organization_id,project_id:$project_id,
      service_instance_id:$service_instance_id,principal_id:$principal_id,
      permissions:["syouyu.credential.create","syouyu.credential.read",
        "syouyu.credential.revoke","syouyu.overview.read","syouyu.usage.read"],
      credential_limits:{max_credentials_per_bucket:10,max_total_credentials:1000},
      issued_at:$iat,expires_at:($iat+60),context_id:$context_id}')"
  PRINCIPAL_TIMESTAMP="${now}"
  PRINCIPAL_ENCODED="$(printf '%s' "${principal}" | base64url)"
  hmac_key="$(<"${workdir}/principal-hmac")"
  PRINCIPAL_SIGNATURE="$(printf '%s.%s' "${PRINCIPAL_TIMESTAMP}" "${PRINCIPAL_ENCODED}" | \
    openssl dgst -sha256 -mac HMAC -macopt "key:${hmac_key}" -binary | base64url)"
}

principal_request() {
  local method=$1 path=$2 body=$3 output=$4 idempotency_key=${5:-} status
  local -a args
  sign_principal
  args=(--silent --show-error --output "${output}" --write-out '%{http_code}'
    --request "${method}"
    --header "x-syouyu-principal: ${PRINCIPAL_ENCODED}"
    --header "x-syouyu-timestamp: ${PRINCIPAL_TIMESTAMP}"
    --header "x-syouyu-signature: ${PRINCIPAL_SIGNATURE}")
  if [[ -n ${idempotency_key} ]]; then
    args+=(--header "Idempotency-Key: ${idempotency_key}")
  fi
  if [[ -n ${body} ]]; then
    args+=(--header 'Content-Type: application/json' --data-binary "${body}")
  fi
  status="$(curl -q --connect-timeout 5 --max-time 20 \
    "${args[@]}" "${api_endpoint}${path}")"
  printf '%s' "${status}"
}

provider_delete() {
  local attempt jwt_id token status
  for attempt in $(seq 1 5); do
    jwt_id="$(new_uuid)"
    token="$(provider_token service-instance.delete "${jwt_id}" 2)"
    status="$(curl -q --silent --show-error --connect-timeout 5 --max-time 20 \
      --output "${workdir}/service-delete.json" \
      --write-out '%{http_code}' --request DELETE \
      --header "Authorization: Bearer ${token}" \
      --header "Idempotency-Key: ${jwt_id}" \
      "${api_endpoint}/internal/v1/service-instances/${service_id}?generation=2")" || status=000
    if [[ " ${status} " == *" 200 "* || " ${status} " == *" 202 "* || \
      " ${status} " == *" 404 "* ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

s3_request() {
  curl -q --config "${workdir}/curl-s3.conf" \
    --connect-timeout 5 --max-time 20 "$@"
}

wait_for_s3_endpoint_count() {
  local expected=$1 attempt ready_endpoints=0
  for attempt in $(seq 1 60); do
    if kube_to_file "${workdir}/s3-endpoints.json" -n "${SYOUYU_NAMESPACE}" \
      get endpointslice -l "kubernetes.io/service-name=${S3_SERVICE}" -o json; then
      ready_endpoints="$(jq \
        '[.items[].endpoints[]? | select(.conditions.ready == true)] | length' \
        "${workdir}/s3-endpoints.json")"
      if [[ ${ready_endpoints} -eq ${expected} ]]; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

restore_garage() {
  local restore_failed=false

  if ${garage_isolation_armed}; then
    if kube -n "${SYOUYU_NAMESPACE}" label "pod/${garage_pod}" \
      app.kubernetes.io/component=garage --overwrite >/dev/null 2>&1; then
      garage_isolation_armed=false
    else
      restore_failed=true
    fi
  fi

  if ${garage_recovery_needed} && ! ${restore_failed}; then
    if kube -n "${SYOUYU_NAMESPACE}" wait --for=condition=Ready \
      "pod/${garage_pod}" --timeout=120s >/dev/null 2>&1 && \
      wait_for_s3_endpoint_count 3; then
      garage_recovery_needed=false
    else
      restore_failed=true
    fi
  fi

  ! ${restore_failed}
}

cleanup() {
  local exit_status=$? status cleanup_failed=false
  trap - EXIT HUP INT TERM
  set +e

  if ! restore_garage; then
    log "ERROR: failed to restore ${garage_pod} after failure injection" >&2
    cleanup_failed=true
  fi

  if ${object_created} && [[ -s ${workdir}/curl-s3.conf ]]; then
    status="$(s3_request --silent --show-error --output "${workdir}/object-delete.xml" \
      --write-out '%{http_code}' --request DELETE \
      "${S3_ENDPOINT}/${bucket_name}/${object_key}" 2>/dev/null)"
    if [[ ${status} != 204 && ${status} != 200 ]]; then
      :
    else
      object_created=false
    fi
  fi

  if ${credential_created}; then
    if [[ ! -s ${workdir}/credential-id && -s ${workdir}/credential.json ]]; then
      jq -er '.credential.id' "${workdir}/credential.json" \
        >"${workdir}/credential-id" 2>/dev/null
    fi
    if [[ -s ${workdir}/credential-id ]]; then
      status="$(principal_request DELETE \
        "/v1/credentials/$(<"${workdir}/credential-id")" '' \
        "${workdir}/credential-delete.json" "$(new_uuid)" 2>/dev/null)"
      if [[ ${status} == 200 || ${status} == 404 ]]; then
        credential_created=false
      fi
    fi
  fi

  if ${service_created}; then
    if provider_delete; then
      service_created=false
      credential_created=false
      object_created=false
    else
      cleanup_failed=true
    fi
  fi

  if ${garage_isolation_armed} || ${garage_recovery_needed} || ${service_created} || \
    ${credential_created} || ${object_created}; then
    cleanup_failed=true
  fi

  find "${workdir}" -depth -delete 2>/dev/null
  if ${cleanup_failed} && [[ ${exit_status} -eq 0 ]]; then
    exit_status=1
  fi
  exit "${exit_status}"
}
trap cleanup EXIT HUP INT TERM

for command in base64 cmp curl jq kubectl openssl tr; do
  command -v "${command}" >/dev/null || fail "required command is missing: ${command}"
done
if [[ -z ${PUBLIC_IPS} ]]; then
  command -v getent >/dev/null || fail 'required command is missing: getent'
fi
[[ -r ${KUBECONFIG} ]] || fail "kubeconfig is not readable: ${KUBECONFIG}"

if [[ ${S3_ENDPOINT} =~ ^https?://([^/:]+)(:([0-9]+))?(/.*)?$ ]]; then
  s3_host="${BASH_REMATCH[1]}"
  s3_port="${BASH_REMATCH[3]}"
else
  fail "S3 endpoint must be an HTTP(S) URL"
fi
if [[ -z ${s3_port} ]]; then
  if [[ ${S3_ENDPOINT} == https://* ]]; then
    s3_port=443
  else
    s3_port=80
  fi
fi
mapfile -t public_ips < <(resolve_public_ips)
[[ ${#public_ips[@]} -gt 0 ]] \
  || fail "S3 endpoint host did not resolve to an IPv4 address: ${s3_host}"
for public_ip in "${public_ips[@]}"; do
  [[ ${public_ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] \
    || fail "invalid public IPv4 address: ${public_ip}"
done

kube_to_file "${workdir}/provider-secret.json" -n "${HETEROCLOUD_NAMESPACE}" \
  get secret "${PROVIDER_SECRET}" -o json
jq -er '.data["ed25519-private.pem"]' "${workdir}/provider-secret.json" | \
  base64 --decode >"${workdir}/provider-private.pem"
kube_to_file "${workdir}/principal-secret.json" -n "${HETEROCLOUD_NAMESPACE}" \
  get secret "${PRINCIPAL_SECRET}" -o json
jq -er '.data["hmac-secret"]' "${workdir}/principal-secret.json" | \
  base64 --decode >"${workdir}/principal-hmac"

kube_to_file "${workdir}/api-pods.json" -n "${SYOUYU_NAMESPACE}" get pods \
  -l app.kubernetes.io/component=api -o json
api_ip="$(jq -er \
  '[.items[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
   | .[0].status.podIP' "${workdir}/api-pods.json")"
api_endpoint="http://${api_ip}:8080"
curl -q --fail --silent --show-error --connect-timeout 5 --max-time 20 \
  "${api_endpoint}/health/ready" >/dev/null

kube_to_file "${workdir}/garage-pod.json" -n "${SYOUYU_NAMESPACE}" \
  get "pod/${garage_pod}" -o json
jq -e '.metadata.labels["app.kubernetes.io/component"] == "garage" and
  any(.status.conditions[]?; .type == "Ready" and .status == "True")' \
  "${workdir}/garage-pod.json" >/dev/null \
  || fail "${garage_pod} is not a ready Garage pod"
kube_to_file "${workdir}/network-policies.json" -n "${SYOUYU_NAMESPACE}" \
  get networkpolicy -o json
jq -e --slurpfile pod "${workdir}/garage-pod.json" '
  any(.items[];
    ((.spec.policyTypes // []) | index("Ingress")) != null and
    ((.spec.policyTypes // []) | index("Egress")) != null and
    ((.spec.ingress // []) | length) == 0 and
    ((.spec.egress // []) | length) == 0 and
    ((.spec.podSelector.matchExpressions // []) | length) == 0 and
    (((.spec.podSelector.matchLabels // {}) |
      has("app.kubernetes.io/component")) | not) and
    all((.spec.podSelector.matchLabels // {} | to_entries)[];
      $pod[0].metadata.labels[.key] == .value))' \
  "${workdir}/network-policies.json" >/dev/null \
  || fail "${garage_pod} is not covered by an ingress/egress default-deny policy"
wait_for_s3_endpoint_count 3 \
  || fail 'S3 service does not have three ready Garage endpoints before the test'

log "reconciling an isolated service bucket"
reconcile_id="$(new_uuid)"
reconcile_token="$(provider_token service-instance.reconcile "${reconcile_id}")"
reconcile_body="$(jq -cn --arg name "syouyu-live-e2e" --arg region "${STORAGE_REGION}" \
  --arg bucket "${bucket_name}" \
  '{generation:1,name:$name,spec:{region:$region,bucket_name:$bucket,
    quota_bytes:16777216,quota_objects:100}}')"
service_created=true
status="$(curl -q --silent --show-error --connect-timeout 5 --max-time 20 \
  --output "${workdir}/reconcile.json" \
  --write-out '%{http_code}' --request PUT \
  --header "Authorization: Bearer ${reconcile_token}" \
  --header "Idempotency-Key: ${reconcile_id}" \
  --header 'Content-Type: application/json' --data-binary "${reconcile_body}" \
  "${api_endpoint}/internal/v1/service-instances/${service_id}")"
require_status "${status}" '200 202' 'service reconcile'

log "issuing one bucket-scoped S3 credential"
credential_created=true
status="$(principal_request POST /v1/credentials \
  '{"name":"live-e2e","permissions":{"read":true,"write":true}}' \
  "${workdir}/credential.json" "$(new_uuid)")"
require_status "${status}" '201' 'credential issue'
jq -er '.credential.id' "${workdir}/credential.json" >"${workdir}/credential-id"
jq -er '.credential.access_key_id' "${workdir}/credential.json" >"${workdir}/access-key"
jq -er '.secret_access_key' "${workdir}/credential.json" >"${workdir}/secret-key"
[[ "$(jq -er '.bucket_name' "${workdir}/credential.json")" == "${bucket_name}" ]] \
  || fail 'credential was issued for an unexpected bucket'

printf 'aws-sigv4 = "aws:amz:%s:s3"\nuser = "%s:%s"\n' \
  "${STORAGE_REGION}" "$(<"${workdir}/access-key")" "$(<"${workdir}/secret-key")" \
  >"${workdir}/curl-s3.conf"
printf 'Syouyu live E2E payload %s\n' "${service_id}" >"${workdir}/payload"

log "running SigV4 PUT, GET, and LIST"
object_created=true
status="$(s3_request --silent --show-error --output "${workdir}/put.xml" \
  --write-out '%{http_code}' --upload-file "${workdir}/payload" \
  "${S3_ENDPOINT}/${bucket_name}/${object_key}")"
require_status "${status}" '200' 'S3 PUT'
status="$(s3_request --silent --show-error --output "${workdir}/download" \
  --write-out '%{http_code}' "${S3_ENDPOINT}/${bucket_name}/${object_key}")"
require_status "${status}" '200' 'S3 GET'
cmp --silent "${workdir}/payload" "${workdir}/download" || fail 'S3 GET payload mismatch'
status="$(s3_request --silent --show-error --output "${workdir}/list.xml" \
  --write-out '%{http_code}' "${S3_ENDPOINT}/${bucket_name}?list-type=2&prefix=e2e%2F")"
require_status "${status}" '200' 'S3 LIST'
grep -Fq "<Key>${object_key}</Key>" "${workdir}/list.xml" \
  || fail 'S3 LIST did not include the uploaded object'

log "isolating ${garage_pod} and testing all public gateways"
garage_isolation_armed=true
garage_recovery_needed=true
# The base default-deny policy still selects this Pod after the Garage selector
# label is removed, isolating RPC and S3 traffic without restarting it or its PVCs.
kube -n "${SYOUYU_NAMESPACE}" label "pod/${garage_pod}" \
  app.kubernetes.io/component- >/dev/null
wait_for_s3_endpoint_count 2 \
  || fail 'S3 service did not converge to two ready Garage endpoints'

for public_ip in "${public_ips[@]}"; do
  status="$(s3_request --silent --show-error --output "${workdir}/failover-${public_ip}" \
    --write-out '%{http_code}' --resolve "${s3_host}:${s3_port}:${public_ip}" \
    "${S3_ENDPOINT}/${bucket_name}/${object_key}")"
  require_status "${status}" '200' "S3 failover GET through ${public_ip}"
  cmp --silent "${workdir}/payload" "${workdir}/failover-${public_ip}" \
    || fail "S3 failover payload mismatch through ${public_ip}"
done

restore_garage || fail "failed to restore ${garage_pod} after failure injection"

log 'deleting the object and confirming empty usage'
status="$(s3_request --silent --show-error --output "${workdir}/object-delete.xml" \
  --write-out '%{http_code}' --request DELETE \
  "${S3_ENDPOINT}/${bucket_name}/${object_key}")"
require_status "${status}" '200 204' 'S3 DELETE'
object_created=false

for _ in $(seq 1 30); do
  status="$(principal_request GET /v1/usage '' "${workdir}/usage.json")"
  require_status "${status}" '200' 'usage read'
  if jq -e '.bytes_used == 0 and .objects_used == 0 and
    .unfinished_upload_bytes == 0 and .unfinished_uploads == 0' \
    "${workdir}/usage.json" >/dev/null; then
    break
  fi
  sleep 1
done
jq -e '.bytes_used == 0 and .objects_used == 0 and
  .unfinished_upload_bytes == 0 and .unfinished_uploads == 0' \
  "${workdir}/usage.json" >/dev/null || fail 'bucket usage did not return to zero'

log 'revoking the credential and deleting the test service'
status="$(principal_request DELETE "/v1/credentials/$(<"${workdir}/credential-id")" '' \
  "${workdir}/credential-delete.json" "$(new_uuid)")"
require_status "${status}" '200' 'credential revoke'
credential_created=false
provider_delete || fail 'service deletion failed'
service_created=false

log 'PASS: S3 data path and one-Garage-node failover are healthy'
