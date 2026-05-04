pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

// HashPreimage: Proves knowledge of hash preimage
// Proves: "I know preimage such that Poseidon(preimage) = hash"
// without revealing preimage.
//
// Constraints: ~240 (Poseidon hash circuit)
// Usage:
//   Input:  { "preimage": "12345", "hash": "<poseidon_hash_of_12345>" }
//   The hash value must be computed separately using snarkjs/circomlib.

template HashPreimage() {
    // Private input: the secret preimage
    signal input preimage;

    // Public input: the known hash
    signal input hash;

    // Instantiate Poseidon hasher for 1 input
    component hasher = Poseidon(1);
    hasher.inputs[0] <== preimage;

    // Constraint: computed hash must equal provided hash
    hash === hasher.out;
}

component main { public [hash] } = HashPreimage();
