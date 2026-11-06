"""
wallet_service/routers/present_zkp.py

POST /wallets/:did/present-zkp
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import PresentZKPRequest
from models.responses import ZKPResponse
from services.selective_disclosure import get_credentials_for_presentation
from services.bbs_prover import generate_bbs_proof
from services.snark_prover import generate_snark_proof

router = APIRouter(prefix="/wallets", tags=["presentation"])
logger = logging.getLogger(__name__)


@router.post("/{did}/present-zkp", response_model=ZKPResponse)
async def present_zkp(did: str, request: PresentZKPRequest):
    """Present with zero-knowledge proof."""
    try:
        proof_type = request.predicate.get("proofType")

        # Get credentials
        credentials = await get_credentials_for_presentation(did, [request.required_type])
        if not credentials:
            raise ValueError(f"No credentials found for type {request.required_type}")

        cred = credentials[0]

        if proof_type == "BbsBlsSignature2020":
            # BBS+ path
            bbs_public_key = cred[10].get("bbsPublicKey") if cred[10] else None
            if not bbs_public_key:
                raise ValueError("BBS+ public key not found")

            disclosed_attrs = request.predicate.get("disclosedAttributes", [])
            result = await generate_bbs_proof(
                cred,  # encrypted VC - should decrypt first
                bbs_public_key,
                disclosed_attrs,
                request.nonce
            )

        elif proof_type == "Groth16":
            # zk-SNARK path
            circuit_id = request.predicate.get("circuitId", "compliance_predicate")
            result = await generate_snark_proof(cred, circuit_id, request.predicate.get("publicInputs", {}))

        else:
            raise ValueError(f"Unknown proof type: {proof_type}")

        return ZKPResponse(
            zkp_proof=result.get("proof"),
            public_inputs=result.get("publicSignals")
        )

    except Exception as e:
        logger.error(f"ZKP presentation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
