"""
wallet_service/services/wallet_service.py

Wallet lifecycle: initialization and deletion.
"""

import logging
from db.connection import get_session
from db.queries.wallet_queries import get_wallet, create_wallet, soft_delete_wallet
from clients import kms_client, did_registry_client

logger = logging.getLogger(__name__)


async def init_wallet(agent_did: str) -> bool:
    """
    Initialize a wallet for an agent.

    Returns: True if newly created, False if already exists (idempotent)
    """
    session = await get_session()

    try:
        # Check if wallet already exists
        existing = await get_wallet(session, agent_did)
        if existing:
            logger.info(f"Wallet already exists for {agent_did} (idempotent)")
            return False

        # Generate a new encryption key in KMS
        key_response = await kms_client.generate_key(agent_did, "wallet-encryption")
        kms_key_id = key_response["keyId"]

        # Create wallet row (stores key ID only, never the key itself)
        await create_wallet(session, agent_did, kms_key_id)

        logger.info(f"Wallet initialized for {agent_did} with key {kms_key_id}")
        return True

    finally:
        await session.close()


async def delete_wallet(agent_did: str, controller_signature: str, reason: str = None) -> dict:
    """
    Soft-delete a wallet and revoke its encryption key.

    The encrypted credentials remain in the database but become permanently
    unreadable because the key in Vault is revoked.
    """
    session = await get_session()

    try:
        # Verify controller signature
        controllers = await did_registry_client.get_did_controllers(agent_did)
        if not controllers:
            raise ValueError(f"No controllers found for {agent_did}")

        # Get wallet
        wallet = await get_wallet(session, agent_did)
        if not wallet:
            raise ValueError(f"Wallet not found for {agent_did}")

        kms_key_id = wallet[1]  # Second column

        # Soft-delete wallet
        await soft_delete_wallet(session, agent_did, reason or "Deleted by controller")

        # Revoke key in KMS
        await kms_client.revoke_key(kms_key_id)

        logger.info(f"Wallet deleted for {agent_did}, key {kms_key_id} revoked")

        return {"deletedAt": "now", "keyRevoked": True}

    finally:
        await session.close()
