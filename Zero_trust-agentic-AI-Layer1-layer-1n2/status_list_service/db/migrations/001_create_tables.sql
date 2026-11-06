CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- status_lists table: one row per status list (holds up to 131,072 credentials)
CREATE TABLE IF NOT EXISTS status_lists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_did TEXT NOT NULL,
    bitstring BYTEA NOT NULL,                   -- raw bytes, GZIP before serving
    total_bits INTEGER NOT NULL DEFAULT 131072,
    next_free_index INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_status_lists_issuer_did ON status_lists(issuer_did);

-- status_list_entries table: maps every vcId to its list + index
CREATE TABLE IF NOT EXISTS status_list_entries (
    vc_id TEXT PRIMARY KEY,
    issuer_did TEXT NOT NULL,
    status_list_id UUID NOT NULL REFERENCES status_lists(id) ON DELETE CASCADE,
    bit_index INTEGER NOT NULL,
    status_list_url TEXT NOT NULL,
    allocated_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_status_list_entries_issuer_did ON status_list_entries(issuer_did);
CREATE INDEX IF NOT EXISTS idx_status_list_entries_status_list_id ON status_list_entries(status_list_id);
CREATE INDEX IF NOT EXISTS idx_status_list_entries_revoked_at ON status_list_entries(revoked_at);

-- revocation_log table: append-only audit of every revocation event
CREATE TABLE IF NOT EXISTS revocation_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vc_id TEXT,
    agent_did TEXT,
    authority_did TEXT NOT NULL,
    reason TEXT NOT NULL,
    bit_index INTEGER,
    status_list_id UUID,
    kafka_event_id TEXT,
    cascade_steps JSONB,                       -- for agent revocations
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_revocation_log_vc_id ON revocation_log(vc_id);
CREATE INDEX IF NOT EXISTS idx_revocation_log_agent_did ON revocation_log(agent_did);
CREATE INDEX IF NOT EXISTS idx_revocation_log_authority_did ON revocation_log(authority_did);
CREATE INDEX IF NOT EXISTS idx_revocation_log_created_at ON revocation_log(created_at);
