# HeteroCloud Syouyu

HeteroCloud Syouyu is the managed S3-compatible object-storage provider for
HeteroCloud. One HeteroCloud `syouyu` service instance represents exactly one
globally named S3 bucket. Syouyu owns that bucket's access keys, quota, usage,
and lifecycle. It does not own customer accounts, organizations, projects,
billing, or IAM policy.

## Components

| Component | Responsibility |
| --- | --- |
| `syouyu-api` | Authenticated provider reconciliation and storage management API |
| PostgreSQL | Durable tenant, bucket, access-key metadata, operations, and audit state |
| Garage | Upstream distributed S3-compatible object data plane |
| Prometheus and Grafana | Capacity, request, latency, repair, and durability monitoring |

Syouyu does not reimplement the S3 data plane. Garage is an independently
licensed upstream dependency. Syouyu wraps its scoped administration API with
HeteroCloud tenancy, idempotency, quota enforcement, and audit behavior.

## Trust Boundary

Only HeteroCloud's provider worker calls `/internal/v1/*`. Requests use a
short-lived EdDSA JWT and an `Idempotency-Key` equal to the token's `jti`.
Syouyu validates issuer, audience, action, organization, project, service,
generation, and request-body reuse before changing Garage state.

Customer applications use the public S3 endpoint with a bucket-scoped access
key. Garage's administration endpoint and Syouyu's provider endpoint are never
published to the internet.

## APIs

| Method and path | Result |
| --- | --- |
| `PUT /internal/v1/service-instances/{id}` | Reconcile the bucket represented by a service instance |
| `DELETE /internal/v1/service-instances/{id}` | Remove an empty bucket after revoking its keys |
| `GET /v1/service-overview` | Return the signed principal's bucket metadata |
| `GET /v1/usage` | Return current bytes, objects, multipart bytes, and key count |
| `GET/POST /v1/credentials` | List or issue bucket-scoped keys |
| `DELETE /v1/credentials/{credential_id}` | Revoke an access key |

The internal provider routes require the short-lived EdDSA provider JWT. The
`/v1/*` routes require HeteroCloud's short-lived, service-scoped HMAC principal
headers. They are intended to be reached through the authenticated
HeteroCloud API proxy, not exposed directly to browsers.

Interactive OpenAPI documentation is available at `/docs`; the machine-
readable document is served at `/openapi.json`.

## License

Syouyu-authored code is licensed under the MIT License. See [LICENSE](LICENSE).
Upstream component licenses continue to apply to their respective images and
packages.
