-- Wallet storage schema

CREATE TABLE IF NOT EXISTS wallets (
    agent_did TEXT PRIMARY KEY,
    kms_key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    deletion_reason TEXT
);

CREATE TABLE IF NOT EXISTS wallet_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_did TEXT NOT NULL REFERENCES wallets(agent_did),
    vc_id TEXT NOT NULL UNIQUE,
    credential_type TEXT[] NOT NULL,
    issuer_did TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    encrypted_vc BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    proof_type TEXT NOT NULL,
    bbs_binding JSONB,
    status TEXT NOT NULL DEFAULT 'active',
    stored_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wc_agent_type ON wallet_credentials (agent_did, credential_type);
CREATE INDEX IF NOT EXISTS idx_wc_agent_issuer ON wallet_credentials (agent_did, issuer_did);
CREATE INDEX IF NOT EXISTS idx_wc_agent_issued ON wallet_credentials (agent_did, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_wc_vc_id ON wallet_credentials (vc_id);
