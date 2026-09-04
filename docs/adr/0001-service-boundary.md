# ADR 0001: Syouyu service and Garage data-plane boundary

- Status: Accepted
- Date: 2026-09-04
- Owners: HeteroCloud platform team

## Context

HeteroCloud needs durable object storage that can be consumed through standard
S3 clients and attached to ephemeral Flash workloads. Object data must survive
Flash Pod replacement, while tenancy, quotas, credentials, auditing, and
HeteroCloud provider reconciliation remain under HeteroCloud control.

Implementing an S3 protocol server and distributed object store inside Syouyu
would duplicate mature storage work and make durability dependent on a new
implementation. Syouyu therefore needs a strict boundary between its managed
control plane and an upstream S3 data plane.

## Decision

Syouyu is the HeteroCloud storage control plane. Garage v2.3.0 is the upstream
S3-compatible data plane.

Syouyu owns:

- HeteroCloud service-instance reconciliation and generations
- organization, project, and service-instance isolation
- bucket lifecycle policy and quota checks
- scoped access-key lifecycle and one-time secret delivery
- idempotency receipts, revocation state, audit records, and usage aggregation
- the stable public endpoint returned to HeteroCloud clients

Garage owns:

- S3 request handling and AWS Signature Version 4 verification
- object metadata and object blocks
- multipart uploads, replication, repair, and cluster layout
- low-level bucket and access-key primitives invoked by Syouyu

PostgreSQL stores Syouyu control-plane state. It does not store object payloads
or Garage's replicated metadata.

## Deployment topology

Garage runs as one three-replica StatefulSet with these fixed safety properties:

- Garage image `dxflrs/garage:v2.3.0`
- replication factor 3
- `consistent` consistency mode
- one logical failure zone per replica
- required Pod anti-affinity across Kubernetes nodes
- one RWO metadata PVC and one RWO data PVC per Pod
- a PodDisruptionBudget requiring two Garage Pods

With RF=3 in consistent mode, normal reads and writes require a quorum of two.
One Garage node can be unavailable without stopping reads or writes. Replication
is not a backup; operators must separately protect metadata snapshots and
object data against deletion, credential compromise, and cluster-wide loss.

Syouyu API runs as three stateless replicas with a two-replica disruption
budget. API state is shared through PostgreSQL. A rolling update may replace API
Pods without replacing Garage Pods or their PVCs.

## Endpoint boundary

The chart creates separate Services:

| Endpoint | Exposure | Purpose |
| --- | --- | --- |
| `*-api` | ClusterIP only | HeteroCloud provider and storage management API |
| `*-garage-admin` | ClusterIP only | HA Garage administration endpoint used by Syouyu |
| `*-garage-admin-bootstrap` | ClusterIP, pinned to Garage ordinal 0 | Serialized cluster-layout changes |
| `*-s3` | ClusterIP, Gateway API backend | Public S3 data plane |
| `*-garage-metrics` | Headless ClusterIP | Per-node Prometheus targets |

Only the S3 Service is eligible for public Gateway routing. Garage admin is not
an HTTPRoute backend and NetworkPolicies limit it to Syouyu API, the layout Job,
and configured monitoring peers.

The S3 Service supports path-style requests at the configured endpoint and
virtual-host requests beneath `garage.config.s3RootDomain`. Public DNS and the
Gateway certificate must cover both the endpoint hostname and wildcard bucket
hostname when virtual-host addressing is enabled.

## Provider authentication

HeteroCloud signs provider requests with short-lived EdDSA JWTs. Syouyu receives
only the public verification key set. The HeteroCloud private signing key must
never be mounted into Syouyu or Garage.

Syouyu validates issuer, audience `heterocloud-syouyu`, `kid`, action, subject,
organization, project, service instance, generation, `jti`, `nbf`, and expiry.
The maximum token lifetime is 60 seconds. `Idempotency-Key` must equal `jti` for
mutating provider operations.

Garage RPC, admin, and metrics credentials are supplied through a pre-existing
Kubernetes Secret. The default chart does not generate or embed production
credentials. The optional chart-managed Secret mode exists only for isolated
development and CI rendering.

## Layout bootstrap

Garage does not create a storage layout merely by starting its Pods. A Helm
post-install/post-upgrade Job waits until all three desired Garage hostnames are
connected, reads the current layout from Garage Admin API v2, and computes role
changes.

The Job sends all role updates and the layout apply call to the ordinal-0 admin
Service. This obeys Garage's requirement that one node receive a complete set
of staged layout changes. It applies exactly `current layout version + 1`.

The Job is idempotent:

- a matching layout exits without an update
- failure after staging repeats the same desired roles, then applies them
- failure after a successful apply observes the matching layout and exits
- concurrent layout writers are outside this bootstrap contract and must be
  excluded operationally

The Job does not remove unknown nodes. Node removal and data draining are
explicit operator actions because automatic removal can destroy the only
remaining copy during a wider incident.

## Network and observability

Default-deny NetworkPolicies separate S3, Garage RPC/admin, Syouyu API,
PostgreSQL, Kubernetes discovery, DNS, and monitoring traffic. Kubernetes API
and external PostgreSQL CIDRs are values because their addresses are specific
to each cluster.

ServiceMonitor resources scrape Syouyu API metrics and every Garage node.
Garage metrics use a bearer token from the existing Secret. At minimum,
operators should alert on cluster availability, connected storage nodes,
partition quorum, repair failures, capacity, API error rate, and Syouyu
reconciliation failures.

## Consequences

- Flash root filesystems remain disposable; applications persist objects by
  using S3 or an explicitly configured object mount.
- An S3 mount is not a fully POSIX filesystem. Git repositories, SQLite files,
  locks, and rename-heavy build trees require a separate workspace service.
- Increasing a StatefulSet PVC requires storage-class expansion and operational
  coordination; Helm cannot shrink existing PVCs.
- Changing Garage replication factor is not a routine chart update and is
  intentionally rejected by the schema.
- Garage remains an independently licensed upstream component. Its container
  and source retain the upstream AGPL-3.0 license; Syouyu-authored code remains
  MIT licensed and does not incorporate Garage into the Syouyu binary.

## References

- [Garage v2.3.0 configuration](https://github.com/deuxfleurs-org/garage/blob/v2.3.0/doc/book/reference-manual/configuration.md)
- [Garage cluster layouts](https://github.com/deuxfleurs-org/garage/blob/v2.3.0/doc/book/operations/layout.md)
- [Garage Admin API v2](https://github.com/deuxfleurs-org/garage/blob/v2.3.0/doc/api/garage-admin-v2.json)
- [Garage Kubernetes deployment](https://github.com/deuxfleurs-org/garage/blob/v2.3.0/doc/book/cookbook/kubernetes.md)
