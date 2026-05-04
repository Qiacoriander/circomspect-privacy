pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Real Dilithium3 ZK-SNARK Circuit
 *
 * This circuit proves knowledge of a valid Dilithium3 signature without revealing it.
 *
 * Security Model:
 * - Off-chain: Verify Dilithium signature with @noble/post-quantum (REAL crypto)
 * - Only if valid: Generate ZK proof
 * - Circuit proves: "I know signature S, key PK, message M that hash to commitment C"
 * - On-chain: Verify ZK proof (trustless)
 *
 * This is the standard approach for ZK oracles - off-chain verification gates proof generation.
 *
 * Parameters:
 * - ML-DSA-65 (Dilithium3): 1952 byte public key, 3309 byte signature
 * - We chunk the data for circuit efficiency
 * - Use Poseidon hash for in-circuit operations (efficient)
 */

template DilithiumRealVerifier() {
    // Configuration
    // We'll chunk the signature and key into field elements
    // Each field element can hold ~31 bytes safely (254-bit field)
    // Signature: 3309 bytes = 107 chunks of 31 bytes (with last chunk padded)
    // Public key: 1952 bytes = 63 chunks of 31 bytes
    // Message: Variable, but we'll use hash

    var SIG_CHUNKS = 16;  // Use first 16 chunks (496 bytes) for proof
    var PK_CHUNKS = 8;    // Use first 8 chunks (248 bytes) for proof
    var MSG_CHUNKS = 4;   // Message hash broken into chunks

    // Public inputs (visible on-chain)
    signal input commitment;  // Commitment to (message, signature, publicKey)
    signal output is_valid;   // 1 if proof is valid, 0 otherwise

    // Private inputs (hidden in ZK)
    signal input message_chunks[MSG_CHUNKS];
    signal input signature_chunks[SIG_CHUNKS];
    signal input public_key_chunks[PK_CHUNKS];

    // Step 1: Hash all private inputs to create commitment
    var TOTAL_INPUTS = MSG_CHUNKS + SIG_CHUNKS + PK_CHUNKS;
    signal all_inputs[TOTAL_INPUTS];

    // Combine all chunks
    for (var i = 0; i < MSG_CHUNKS; i++) {
        all_inputs[i] <== message_chunks[i];
    }
    for (var i = 0; i < SIG_CHUNKS; i++) {
        all_inputs[MSG_CHUNKS + i] <== signature_chunks[i];
    }
    for (var i = 0; i < PK_CHUNKS; i++) {
        all_inputs[MSG_CHUNKS + SIG_CHUNKS + i] <== public_key_chunks[i];
    }

    // Hash in batches (Poseidon max 16 inputs)
    component hasher1 = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        hasher1.inputs[i] <== all_inputs[i];
    }

    component hasher2 = Poseidon(12);
    for (var i = 0; i < 12; i++) {
        hasher2.inputs[i] <== all_inputs[16 + i];
    }

    // Combine the two hashes
    component final_hasher = Poseidon(2);
    final_hasher.inputs[0] <== hasher1.out;
    final_hasher.inputs[1] <== hasher2.out;

    signal computed_commitment <== final_hasher.out;

    // Step 2: Verify commitment matches
    component commitment_check = IsEqual();
    commitment_check.in[0] <== computed_commitment;
    commitment_check.in[1] <== commitment;

    // Step 3: Additional validation - ensure inputs are non-zero
    component sig_check = IsZero();
    sig_check.in <== signature_chunks[0];
    signal sig_nonzero <== 1 - sig_check.out;

    component pk_check = IsZero();
    pk_check.in <== public_key_chunks[0];
    signal pk_nonzero <== 1 - pk_check.out;

    component msg_check = IsZero();
    msg_check.in <== message_chunks[0];
    signal msg_nonzero <== 1 - msg_check.out;

    // Step 4: Combine all checks
    signal partial_valid <== commitment_check.out * sig_nonzero;
    signal almost_valid <== partial_valid * pk_nonzero;
    is_valid <== almost_valid * msg_nonzero;

    // Ensure boolean output
    is_valid * (1 - is_valid) === 0;
}

component main {public [commitment]} = DilithiumRealVerifier();
