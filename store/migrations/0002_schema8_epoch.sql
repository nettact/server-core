-- Schema 8 (CLOUD-013C): enrollment epochs and the durable packet-receipt
-- ledger.
--
-- An agent credential now belongs to a GENERATION. enrollment_epoch advances on
-- every credential replacement of an existing agent — the controlled wire
-- rotation (EpochRotationResult) and a reinstall re-enrollment alike — so a
-- fresh WAL allocator can restart at sequence 1 without ever reusing an
-- (agent, epoch, sequence) identity that has already been committed. Fresh
-- enrollments are generation 1; pre-schema-8 rows get that default on upgrade.
--
-- The two pending_prev_* columns record, for audit and observability, the
-- window in which a committed rotation's OLD token still authenticates (so a
-- rotation result lost in transit can be re-issued idempotently). Only hashes
-- are stored, as everywhere else. The authority for the re-issue itself is the
-- registry's in-memory pending map (the new token's plaintext exists nowhere
-- durable by design); on a restart the window columns remain as audit trail
-- but the re-issue is refused, and the agent's retry loop converges.
--
-- Times are unix seconds, matching the existing schema convention.

ALTER TABLE agents ADD COLUMN enrollment_epoch INTEGER NOT NULL DEFAULT 1;
ALTER TABLE agents ADD COLUMN pending_prev_token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN pending_prev_token_until INTEGER NOT NULL DEFAULT 0;

-- The durable receipt ledger behind sequence-conflict detection: one row per
-- admitted (agent, epoch, sequence), carrying the semantic fingerprint of the
-- content that was admitted (see ingest.PacketFingerprint). A replay whose
-- fingerprint differs — or whose slot has no receipt at all — is a sequence
-- conflict: the batch must never be renumbered in place, so the hub answers it
-- with an epoch rotation challenge. WITHOUT ROWID: the primary key IS the
-- access pattern, and receipts live exactly as long as the agent does (the FK
-- cascades on delete).
CREATE TABLE packet_receipts (
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    enrollment_epoch INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, enrollment_epoch, sequence)
) WITHOUT ROWID;
