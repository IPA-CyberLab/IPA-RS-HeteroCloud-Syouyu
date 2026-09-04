ALTER TABLE syouyu_operation_receipts
    ADD COLUMN lease_attempt BIGINT NOT NULL DEFAULT 1
        CHECK (lease_attempt > 0),
    ADD COLUMN lease_expires_at TIMESTAMPTZ;

-- Receipts left behind by a process running the pre-lease implementation must
-- be reclaimable immediately after this migration is deployed.
UPDATE syouyu_operation_receipts
SET lease_expires_at = clock_timestamp() - interval '1 second'
WHERE state = 'in_progress';

ALTER TABLE syouyu_operation_receipts
    ADD CONSTRAINT syouyu_operation_receipts_lease_state_check CHECK (
        (state = 'in_progress' AND lease_expires_at IS NOT NULL)
        OR (state IN ('succeeded', 'failed') AND lease_expires_at IS NULL)
    );

CREATE INDEX syouyu_operation_receipts_active_lease_idx
    ON syouyu_operation_receipts (
        service_instance_id,
        lease_expires_at,
        created_at
    )
    WHERE state = 'in_progress';
