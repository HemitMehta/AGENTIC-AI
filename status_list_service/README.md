# Status List Service (SS6) — Revocation Backbone

Zero-Trust Agentic AI Layer 1 revocation and blocklist infrastructure.

## Architecture

**5 HTTP Endpoints:**
- `POST /status-lists/allocate` — Allocate VC status entry
- `GET /status-lists/{id}` — Fetch signed Status List 2021 VC
- `POST /status-lists/revoke` — Revoke credential
- `POST /blocklist/{did}` — Blocklist did:key
- `POST /revoke/agent/{did}` — Full cascade revocation

**3 Databases:**
- `status_lists` — 131K-bit lists, one per issuer (per spec)
- `status_list_entries` — Maps VC ID → list + index
- `revocation_log` — Append-only audit trail

**4 Integrations:**
- Redis: Status list cache (30s TTL), ephemeral blocklist
- PostgreSQL: Durable state
- Kafka: Event stream (credential.revoked, agent.revoked)
- KMS: Sign status list VCs

## Revocation Order (Strict)

Redis (immediate) → Postgres (durable) → Kafka (event). Verifiers seeing Redis within milliseconds, Postgres 100ms, Kafka eventual.

## Bit Indexing

Big-endian per StatusList2021 spec: bit 0 = MSB of byte 0.

```python
byte_pos = index // 8
bit_pos = 7 - (index % 8)
```

## Status List VC Structure

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/vc/status-list/2021/v1"],
  "type": ["VerifiableCredential", "StatusList2021Credential"],
  "issuer": "did:web:issuer.example.com",
  "issuedAt": "2026-05-29T00:00:00Z",
  "credentialSubject": {
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "base64url(gzip(131072-bit-string))"
  },
  "proof": { "type": "Ed25519Signature2020", ... }
}
```

## Cascade Revocation (Agent)

6 steps with 3x retry (1s, 2s, 4s backoff):
1. Fetch all unrevoked VCs for agent
2. Revoke all VCs (in parallel)
3. Update DID Document to revoked status
4. Add to ephemeral blocklist (did:key only)
5. Publish Kafka agent.revoked event
6. Notify ANS (Layer 2 deactivation)

All steps idempotent. Already-revoked VCs skipped.

## Configuration

```bash
STATUS_LIST_SERVICE_PORT=8005
STATUS_LIST_BASE_URL=http://localhost:8005
STATUS_CACHE_TTL=30
BITSTRING_SIZE_BITS=131072
KMS_STATUS_LIST_KEY_ID=status-list-signing-key
ANS_URL=http://localhost:9001
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
CASCADE_MAX_RETRIES=3
CASCADE_RETRY_BASE_SECONDS=1
```

## API Examples

### Allocate Status Entry

```bash
curl -X POST http://localhost:8005/status-lists/allocate \
  -H "Content-Type: application/json" \
  -d '{"issuer_did": "did:web:issuer.example.com", "vc_id": "urn:uuid:123"}'

# Response
{
  "status_list_url": "http://localhost:8005/status-lists/list-uuid",
  "bit_index": 42
}
```

### Get Status List VC

```bash
curl http://localhost:8005/status-lists/list-uuid

# Response: Signed Status List 2021 VC (JSON)
```

### Revoke Credential

```bash
curl -X POST http://localhost:8005/status-lists/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "vc_id": "urn:uuid:123",
    "reason": "credential fraud",
    "authority_did": "did:web:authority.example.com"
  }'

# Response
{
  "revoked_at": "2026-05-29T12:34:56Z",
  "bit_index": 42,
  "kafka_event_id": "event-uuid"
}
```

### Revoke Agent (Cascade)

```bash
curl -X POST http://localhost:8005/revoke/agent/did:web:agent.example.com \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "compromised key",
    "authority_did": "did:web:authority.example.com"
  }'

# Response
{
  "cascade_complete": true,
  "steps": [
    {"step": "REVOKE_VCS", "status": "success", "count": 5},
    {"step": "UPDATE_DID_DOCUMENT", "status": "success"},
    {"step": "EPHEMERAL_BLOCKLIST", "status": "success"},
    {"step": "KAFKA_EVENT", "status": "success", "kafka_event_id": "..."},
    {"step": "ANS_DEACTIVATE", "status": "success"}
  ],
  "kafka_event_id": "..."
}
```

## Testing

```bash
# All tests
pytest status_list_service/tests/

# Specific test
pytest status_list_service/tests/test_bitstring_manager.py

# With coverage
pytest --cov=status_list_service status_list_service/tests/
```

## Dependencies

See [requirements.txt](./requirements.txt):
- FastAPI 0.104.1
- asyncpg 0.29.0 (async PostgreSQL)
- redis[asyncio] 5.0.1
- aiokafka 0.11.0
- pynacl 1.5.0
- httpx 0.25.2
- pydantic 2.5.0

## Docker

```bash
docker-compose up status_list_service
```

Depends on: redis, postgres, kafka

## Integration with SS4 & SS5

**SS4 (Issuance):** Calls `POST /status-lists/allocate` on every credential issuance to get `statusListUrl` and `bitIndex`.

**SS5 (Verification):** Calls `GET /status-lists/{id}` to fetch signed VC, decompresses encodedList, checks bit at index.

**Revocation:** Security team calls `POST /status-lists/revoke` to revoke individual credentials or `POST /revoke/agent/{did}` for full cascade.

---

*For details on Zero-Trust Agentic AI Layer 1 architecture, see the root README.*
