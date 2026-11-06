"""
wallet_service/bbs_derive_proof.js
──────────────────────────────────
BBS+ selective disclosure proof generation.
Run via Node subprocess from bbs_prover.py.
"""

const { blsCreateProof } = require('@mattrglobal/bbs-signatures');
const fs = require('fs');

async function main() {
    try {
        const input = JSON.parse(fs.readFileSync('/dev/stdin', 'utf8'));
        
        const proof = await blsCreateProof({
            signature: Buffer.from(input.vc.proof.proofValue, 'base64'),
            publicKey: Buffer.from(input.bbsPublicKey, 'base64'),
            messages: input.vc.credentialSubject.messages.map(m => Buffer.from(m)),
            nonce: Buffer.from(input.nonce),
            revealed: input.disclosedAttributes.map(a => parseInt(a))
        });
        
        process.stdout.write(JSON.stringify({
            derivedProof: Buffer.from(proof).toString('base64'),
            disclosedAttributes: input.disclosedAttributes
        }));
    } catch (e) {
        process.stderr.write(e.message);
        process.exit(1);
    }
}

main();
