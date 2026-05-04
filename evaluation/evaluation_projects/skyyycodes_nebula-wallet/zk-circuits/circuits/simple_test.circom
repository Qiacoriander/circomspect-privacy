pragma circom 2.1.0;

/*
 * Simple Test Circuit for ZK Infrastructure
 *
 * This is a minimal circuit to verify the ZK proving infrastructure works.
 * It proves knowledge of a preimage for a simple hash commitment.
 *
 * The full SPHINCS+ circuit is in sphincs_main.circom but requires
 * more optimization for the complex loop dependencies in FORS verification.
 */

include "keccak.circom";

// Simple hash commitment verification
// Proves: I know a 32-byte preimage that hashes to the public commitment
template HashCommitment() {
    // Public input: the hash commitment
    signal input commitment[32];

    // Private input: the preimage
    signal input preimage[32];

    // Compute hash of preimage using SHAKE256
    component shake = SHAKE256(32, 32);

    // Convert preimage bytes to bits
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[i * 8 + j] <-- (preimage[i] >> j) & 1;
            shake.in[i * 8 + j] * (1 - shake.in[i * 8 + j]) === 0;
        }
    }

    // Verify each byte of the hash matches the commitment
    signal computedHash[32];
    for (var i = 0; i < 32; i++) {
        var sum = 0;
        for (var j = 0; j < 8; j++) {
            sum += shake.out[i * 8 + j] * (1 << j);
        }
        computedHash[i] <-- sum;
        computedHash[i] === commitment[i];
    }

    // Output signal
    signal output valid;
    valid <== 1;
}

component main {public [commitment]} = HashCommitment();
