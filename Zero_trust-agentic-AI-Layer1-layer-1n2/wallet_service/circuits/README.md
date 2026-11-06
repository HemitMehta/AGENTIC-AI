"""
wallet_service/circuits/README.md
─────────────────────────────────
zk-SNARK Circuit Artifacts

This directory contains compiled circuit artifacts (prover and verifier keys).

## Directory Structure

```
circuits/
└── compliance_predicate/          # Example circuit
    ├── circuit.wasm               # Compiled WASM (for proving)
    ├── zkey                       # Proving key
    └── verification_key.json      # Verification key (shared with SS5)
```

## Important

1. **Identical Keys**: The `verification_key.json` in this directory MUST be identical
   to `verification_service/circuits/compliance_predicate/verification_key.json` in SS5.
   If they diverge, proof verification silently fails.

2. **Version Control**: These files should be committed to git. They are build artifacts
   but they establish the contract between prover (SS7) and verifier (SS5).

3. **Recompilation**: If you need to recompile a circuit:
   ```bash
   cd circuits/compliance_predicate
   circom circuit.circom --r1cs --wasm
   snarkjs groth16 setup circuit.r1cs powers_of_tau_final.ptau zkey_0000.zkey
   snarkjs zkey export vkey zkey_0000.zkey verification_key.json
   ```

4. **Symlink Option**: Alternatively, create a symlink so both services reference
   the same verification key file:
   ```bash
   ln -s ../../wallet_service/circuits verification_service/circuits
   ```
"""
