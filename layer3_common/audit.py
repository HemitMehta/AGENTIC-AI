"""Transactional, hash-linked audit events. Not a substitute for external WORM storage."""
import hashlib
from datetime import datetime, timezone

from psycopg2 import sql
from psycopg2.extras import Json

from layer3_common.crypto import canonical

GENESIS = "0" * 64


def initialize(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS layer3_security_events (
            sequence BIGSERIAL PRIMARY KEY,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE,
            event JSONB NOT NULL
        );
        CREATE OR REPLACE FUNCTION layer3_reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Audit records are append-only'; END; $$;
    """)
    protect(cur, "layer3_security_events")


def protect(cur, table):
    cur.execute(sql.SQL("DROP TRIGGER IF EXISTS immutable_audit ON {};").format(sql.Identifier(table)))
    cur.execute(sql.SQL("""CREATE TRIGGER immutable_audit BEFORE UPDATE OR DELETE OR TRUNCATE ON {}
        FOR EACH STATEMENT EXECUTE FUNCTION layer3_reject_audit_mutation();""").format(sql.Identifier(table)))


def append(cur, action, payload, actor):
    # One chain per service schema; the lock lasts until the caller's transaction commits.
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || '.audit', 0))")
    cur.execute("SELECT event_hash FROM layer3_security_events ORDER BY sequence DESC LIMIT 1")
    previous = cur.fetchone()
    previous_hash = previous["event_hash"] if previous else GENESIS
    event = {"action": action, "actor": actor, "recordedAt": datetime.now(timezone.utc).isoformat(), "payload": payload}
    event_hash = hashlib.sha256(canonical({"previousHash": previous_hash, "event": event})).hexdigest()
    cur.execute("INSERT INTO layer3_security_events (previous_hash,event_hash,event) VALUES (%s,%s,%s)",
                (previous_hash, event_hash, Json(event)))


def verify_rows(rows):
    previous, count = GENESIS, 0
    for row in rows:
        expected = hashlib.sha256(canonical({"previousHash": previous, "event": row["event"]})).hexdigest()
        if row["previous_hash"] != previous or row["event_hash"] != expected:
            return {"valid": False, "checked": count, "failedSequence": row["sequence"]}
        previous, count = row["event_hash"], count + 1
    return {"valid": True, "checked": count, "headHash": previous}


def integrity(db):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM layer3_security_events ORDER BY sequence")
        return verify_rows(cur)


def events(db, after, limit):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM layer3_security_events WHERE sequence > %s ORDER BY sequence LIMIT %s",
                    (after, limit))
        return {"events": cur.fetchall()}
