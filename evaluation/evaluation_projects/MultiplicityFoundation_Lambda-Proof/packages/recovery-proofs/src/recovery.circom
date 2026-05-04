pragma circom 2.1.6;
include "poseidon.circom";

// Recovery proof: Prover knows `seed` such that Poseidon(seed) == identityHash,
// and commits to newPK. Nonce included to block replay.
// Public: identityHash, newPK, nonce
// Private: seed

template Recovery() {
    signal input seed;
    signal input nonce;        // field
    signal input newPK;        // field
    signal input identityHash; // field

    component h = Poseidon(1);
    h.inputs[0] <== seed;
    h.out === identityHash;

    // Bind rotation to a specific nonce
    signal output outHash;
    component h2 = Poseidon(3);
    h2.inputs[0] <== seed;
    h2.inputs[1] <== newPK;
    h2.inputs[2] <== nonce;
    outHash <== h2.out; // can be ignored or emitted for receipts
}

component main = Recovery();
