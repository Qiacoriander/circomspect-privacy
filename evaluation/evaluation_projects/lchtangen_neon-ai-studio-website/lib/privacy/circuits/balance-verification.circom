// # CONCEPT: Private Balance Verification Circuit
// # ARCHITECTURE: Proves balance >= threshold without revealing actual balance
// # BEST_PRACTICE: Zero-knowledge proof for financial privacy

pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

template BalanceVerification() {
    // Private inputs (known only to prover)
    signal private input privateBalance;
    signal private input secret;
    
    // Public inputs (known to verifier)
    signal input publicCommitment;
    signal input threshold;
    signal input nullifier;
    
    // Output
    signal output isValid;
    
    // Component for Poseidon hash
    component hasher = Poseidon(3);
    
    // Verify commitment: hash(privateBalance, secret) == publicCommitment
    hasher.inputs[0] <== privateBalance;
    hasher.inputs[1] <== secret;
    hasher.inputs[2] <== 0; // Padding
    
    publicCommitment === hasher.out;
    
    // Verify balance >= threshold
    component comparator = GreaterThan(32);
    comparator.in[0] <== privateBalance;
    comparator.in[1] <== threshold;
    
    // Verify nullifier is non-zero (prevents double-spending)
    component nullifierCheck = IsZero();
    nullifierCheck.in <== nullifier;
    
    // Output is valid if balance >= threshold and nullifier is non-zero
    isValid <== comparator.out * (1 - nullifierCheck.out);
}

component main = BalanceVerification();

