"""
wallet_service/services/bbs_prover.py

BBS+ selective disclosure proof generation.
"""

import json
import subprocess
import logging
import asyncio
from config import NODE_BINARY, BBS_SCRIPT_PATH, BBS_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


async def generate_bbs_proof(
    vc_json: dict,
    bbs_public_key: str,
    disclosed_attributes: list,
    nonce: str
) -> dict:
    """
    Generate a BBS+ derived proof using Node.js subprocess.

    Args:
        vc_json: Decrypted VC object
        bbs_public_key: BBS+ public key (base64)
        disclosed_attributes: List of attribute indices to disclose
        nonce: Verifier nonce

    Returns:
        { derivedProof, disclosedAttributes }
    """

    payload = {
        "vc": vc_json,
        "bbsPublicKey": bbs_public_key,
        "disclosedAttributes": disclosed_attributes,
        "nonce": nonce
    }

    try:
        # Call Node.js script
        process = await asyncio.create_subprocess_exec(
            NODE_BINARY, BBS_SCRIPT_PATH,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        input_json = json.dumps(payload).encode()
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=input_json),
            timeout=BBS_TIMEOUT_SECONDS
        )

        if process.returncode != 0:
            logger.error(f"BBS proof generation failed: {stderr.decode()}")
            raise RuntimeError(f"BBS proof generation failed: {stderr.decode()}")

        result = json.loads(stdout.decode())
        logger.info(f"BBS proof generated with {len(disclosed_attributes)} disclosed attributes")
        return result

    except asyncio.TimeoutError:
        logger.error("BBS proof generation timed out")
        raise RuntimeError("BBS proof generation exceeded timeout")
    except Exception as e:
        logger.error(f"BBS proof generation error: {e}")
        raise
