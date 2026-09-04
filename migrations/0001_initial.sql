CREATE TABLE syouyu_service_instances (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    desired_generation BIGINT NOT NULL CHECK (desired_generation > 0),
    desired_spec JSONB NOT NULL CHECK (jsonb_typeof(desired_spec) = 'object'),
    observed_generation BIGINT NOT NULL CHECK (observed_generation >= 0),
    phase TEXT NOT NULL CHECK (
        phase IN ('provisioning', 'ready', 'degraded', 'deleting', 'deleted', 'error')
    ),
    current_operation_id UUID NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (id, organization_id, project_id),
    UNIQUE (project_id, name),
    CHECK (
        (phase = 'deleted' AND deleted_at IS NOT NULL)
        OR (phase <> 'deleted' AND deleted_at IS NULL)
    )
);

CREATE INDEX syouyu_service_instances_scope_idx
    ON syouyu_service_instances (organization_id, project_id, id);

CREATE TABLE syouyu_bucket_name_reservations (
    bucket_name TEXT PRIMARY KEY CHECK (char_length(bucket_name) BETWEEN 3 AND 63),
    service_instance_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE syouyu_buckets (
    service_instance_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    physical_bucket_id TEXT UNIQUE CHECK (
        physical_bucket_id IS NULL
        OR char_length(physical_bucket_id) BETWEEN 1 AND 256
    ),
    bucket_name TEXT NOT NULL UNIQUE CHECK (char_length(bucket_name) BETWEEN 3 AND 63),
    region TEXT NOT NULL CHECK (char_length(region) BETWEEN 1 AND 64),
    quota_bytes BIGINT NOT NULL CHECK (quota_bytes > 0),
    quota_objects BIGINT NOT NULL CHECK (quota_objects > 0),
    used_bytes BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    used_objects BIGINT NOT NULL DEFAULT 0 CHECK (used_objects >= 0),
    usage_measured_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (service_instance_id, organization_id, project_id)
        REFERENCES syouyu_service_instances (id, organization_id, project_id)
        ON DELETE RESTRICT
);

CREATE INDEX syouyu_buckets_scope_idx
    ON syouyu_buckets (organization_id, project_id, service_instance_id);

CREATE TABLE syouyu_credentials (
    id UUID PRIMARY KEY,
    service_instance_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    garage_key_id TEXT NOT NULL UNIQUE CHECK (char_length(garage_key_id) BETWEEN 1 AND 256),
    access_key_id TEXT NOT NULL UNIQUE CHECK (char_length(access_key_id) BETWEEN 1 AND 256),
    permissions JSONB NOT NULL CHECK (jsonb_typeof(permissions) = 'object'),
    secret_key_fingerprint BYTEA NOT NULL CHECK (octet_length(secret_key_fingerprint) = 32),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    UNIQUE (service_instance_id, name),
    FOREIGN KEY (service_instance_id, organization_id, project_id)
        REFERENCES syouyu_service_instances (id, organization_id, project_id)
        ON DELETE RESTRICT,
    CHECK (
        (status = 'active' AND revoked_at IS NULL AND revoked_by IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)
    )
);

CREATE INDEX syouyu_credentials_scope_created_idx
    ON syouyu_credentials (
        organization_id,
        project_id,
        service_instance_id,
        created_at DESC,
        id DESC
    );

CREATE TABLE syouyu_credential_reservations (
    credential_id UUID PRIMARY KEY,
    operation_id UUID NOT NULL UNIQUE,
    service_instance_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    permissions JSONB NOT NULL CHECK (jsonb_typeof(permissions) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (service_instance_id, name),
    FOREIGN KEY (service_instance_id, organization_id, project_id)
        REFERENCES syouyu_service_instances (id, organization_id, project_id)
        ON DELETE RESTRICT
);

CREATE INDEX syouyu_credential_reservations_organization_idx
    ON syouyu_credential_reservations (organization_id);

CREATE TABLE syouyu_operation_receipts (
    idempotency_key UUID PRIMARY KEY,
    operation_id UUID NOT NULL UNIQUE,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    service_instance_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    generation BIGINT,
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    state TEXT NOT NULL CHECK (state IN ('in_progress', 'succeeded', 'failed')),
    response_status INTEGER CHECK (response_status BETWEEN 100 AND 599),
    response_nonce BYTEA CHECK (octet_length(response_nonce) = 12),
    response_ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (generation IS NULL OR generation > 0),
    CHECK (
        (state = 'in_progress'
            AND response_status IS NULL
            AND response_nonce IS NULL
            AND response_ciphertext IS NULL
            AND completed_at IS NULL)
        OR (state IN ('succeeded', 'failed')
            AND response_status IS NOT NULL
            AND response_nonce IS NOT NULL
            AND response_ciphertext IS NOT NULL
            AND completed_at IS NOT NULL)
    )
);

CREATE INDEX syouyu_operation_receipts_scope_idx
    ON syouyu_operation_receipts (
        organization_id,
        project_id,
        service_instance_id,
        created_at DESC
    );

CREATE TABLE syouyu_audit_events (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    service_instance_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    principal_context_id UUID,
    request_id TEXT NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 256),
    action TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    resource_type TEXT NOT NULL CHECK (char_length(resource_type) BETWEEN 1 AND 64),
    resource_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'failed')),
    details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX syouyu_audit_events_scope_created_idx
    ON syouyu_audit_events (
        organization_id,
        project_id,
        service_instance_id,
        created_at DESC
    );

CREATE TABLE syouyu_usage_snapshots (
    service_instance_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    bytes_used BIGINT NOT NULL CHECK (bytes_used >= 0),
    objects_used BIGINT NOT NULL CHECK (objects_used >= 0),
    measured_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (service_instance_id, organization_id, project_id)
        REFERENCES syouyu_service_instances (id, organization_id, project_id)
        ON DELETE RESTRICT
);
