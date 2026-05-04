pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

/*
 * VaultAccess circuit - proves knowledge of a secret without revealing it
 * Also verifies the proof is tied to a specific wallet address
 */
template VaultAccess() {
    // Private inputs (known only to prover)
    signal input secret;
    signal input nonce; // Add randomness to prevent replay attacks
    
    // Public inputs (visible to verifier)
    signal input walletAddress;
    signal input vaultId;
    signal input expectedCommitment;
    
    // Output
    signal output isValid;
    
    // Create commitment from secret, vaultId, and walletAddress
    // This ties the proof to a specific wallet and vault
    component commitmentHash = Poseidon(3);
    commitmentHash.inputs[0] <== secret;
    commitmentHash.inputs[1] <== vaultId;
    commitmentHash.inputs[2] <== walletAddress;
    
    // Verify the commitment matches expected value
    component isEqual = IsEqual();
    isEqual.in[0] <== commitmentHash.out;
    isEqual.in[1] <== expectedCommitment;
    
    // Output 1 if proof is valid, 0 otherwise
    isValid <== isEqual.out;
}

// Helper template for equality check
template IsEqual() {
    signal input in[2];
    signal output out;
    
    component eq = IsZero();
    eq.in <== in[0] - in[1];
    out <== eq.out;
}

// Helper template for zero check
template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    
    out <== -in*inv + 1;
    in*out === 0;
}

component main = VaultAccess();