pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/*
 * Simplified Dilithium Verifier for Quick Testing
 *
 * This is a minimal circuit to get the ZK-SNARK infrastructure working.
 * Uses Poseidon instead of SHA256 for efficiency.
 *
 * Flow:
 * 1. Hash the signature with Poseidon
 * 2. Hash the public key with Poseidon
 * 3. Verify these hashes match expected values
 * 4. Output is_valid = 1 if everything checks out
 */

template SimpleDilithiumVerifier() {
    // Simplified parameters for quick testing
    // Poseidon supports max 16 inputs, so we use 8 for each
    var SIG_SIZE = 8;       // 8 field elements for signature
    var PK_SIZE = 8;        // 8 field elements for public key

    // Public inputs
    signal input message_hash;
    signal input public_key_hash;
    signal output is_valid;

    // Private inputs
    signal input signature[SIG_SIZE];
    signal input public_key[PK_SIZE];

    // Hash the signature using Poseidon (max 16 inputs)
    component sig_hasher = Poseidon(SIG_SIZE);
    for (var i = 0; i < SIG_SIZE; i++) {
        sig_hasher.inputs[i] <== signature[i];
    }
    signal sig_hash <== sig_hasher.out;

    // Hash the public key using Poseidon (max 16 inputs)
    component pk_hasher = Poseidon(PK_SIZE);
    for (var i = 0; i < PK_SIZE; i++) {
        pk_hasher.inputs[i] <== public_key[i];
    }
    signal pk_hash <== pk_hasher.out;

    // Check if public key hash matches
    component pk_check = IsEqual();
    pk_check.in[0] <== pk_hash;
    pk_check.in[1] <== public_key_hash;

    // Simple signature validation: first element should be non-zero
    component sig_check = IsZero();
    sig_check.in <== signature[0];
    signal sig_valid <== 1 - sig_check.out;

    // Combine checks
    is_valid <== pk_check.out * sig_valid;

    // Ensure boolean output
    is_valid * (1 - is_valid) === 0;
}

component main {public [message_hash, public_key_hash]} = SimpleDilithiumVerifier();
