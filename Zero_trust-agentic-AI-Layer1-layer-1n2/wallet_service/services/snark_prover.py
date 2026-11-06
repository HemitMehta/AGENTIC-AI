"""
wallet_service/services/snark_prover.py

zk-SNARK proof generation via snarkjs.
"""

import json
import subprocess
import logging
import asyncio
from config import NODE_BINARY, SNARK_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)


async def generate_snark_proof(
    vc_json: dict,
    circuit_id: str,
    public_inputs: dict
) -> dict:
    """
    Generate a zk-SNARK proof using snarkjs.

    Args:
        vc_json: Decrypted VC object
        circuit_id: Circuit name (e.g., 'compliance_predicate')
        public_inputs: Public witness values

    Returns:
        { proof, publicSignals }
    """

    # Build private witness from VC
    witness = {
        "vcIssuer": vc_json.get("issuer"),
        "vcExpiryTimestamp": int(vc_json.get("expirationDate", "").split("T")[0].replace("-", "")),
        "vcType": vc_json.get("type", []),
        "vcSignature": vc_json.get("proof", {}).get("proofValue", "")
    }

    # Call snarkjs via Node.js
    snarkjs_code = f"""
const snarkjs = require('snarkjs');
const witness = {json.dumps(witness)};
const wasmPath = './circuits/{circuit_id}/circuit.wasm';
const zkeyPath = './circuits/{circuit_id}/zkey';

snarkjs.groth16.fullProve(witness, wasmPath, zkeyPath)
  .then(({{ proof, publicSignals }}) => {{
    process.stdout.write(JSON.stringify({{ proof, publicSignals }}));
  }})
  .catch(err => {{
    process.stderr.write(err.message);
    process.exit(1);
  }});
"""

    try:
        process = await asyncio.create_subprocess_exec(
            NODE_BINARY, "-e", snarkjs_code,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=SNARK_TIMEOUT_SECONDS
        )

        if process.returncode != 0:
            logger.error(f"SNARK proof generation failed: {stderr.decode()}")
            raise RuntimeError(f"SNARK proof generation failed")

        result = json.loads(stdout.decode())
        logger.info(f"SNARK proof generated for circuit {circuit_id}")
        return result

    except asyncio.TimeoutError:
        logger.error("SNARK proof generation timed out")
        raise RuntimeError("SNARK proof generation exceeded timeout")
    except Exception as e:
        logger.error(f"SNARK proof generation error: {e}")
        raise
