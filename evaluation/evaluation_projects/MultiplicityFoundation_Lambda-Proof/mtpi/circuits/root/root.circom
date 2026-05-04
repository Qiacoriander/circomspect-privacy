pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

// Root circuit sketch capturing public interface documented in docs.
template RootV1() {
    signal input identitySeed;   // private
    signal input seq;            // private counter

    signal input identityHash;   // public
    signal input stateCommit;    // public
    signal input epoch;          // public
    signal input domain;         // public
    signal input chainId;        // public
    signal input nullifier;      // public

    signal nk;
    component poseidonNK = Poseidon(2);
    poseidonNK.inputs[0] <== identitySeed;
    poseidonNK.inputs[1] <== 0; // domain separator "nk" encoded as 0 for stub
    nk <== poseidonNK.out;

    component poseidonId = Poseidon(2);
    poseidonId.inputs[0] <== identitySeed;
    poseidonId.inputs[1] <== 1; // placeholder salt
    poseidonId.out === identityHash;

    component poseidonR = Poseidon(4);
    poseidonR.inputs[0] <== nk;
    poseidonR.inputs[1] <== epoch;
    poseidonR.inputs[2] <== domain;
    poseidonR.inputs[3] <== seq;

    component poseidonNullifier = Poseidon(4);
    poseidonNullifier.inputs[0] <== nk;
    poseidonNullifier.inputs[1] <== poseidonR.out;
    poseidonNullifier.inputs[2] <== epoch;
    poseidonNullifier.inputs[3] <== domain;
    poseidonNullifier.out === nullifier;

    // Additional state transition logic should enforce validity rules and
    // Merkle membership; omitted for brevity. This stub focuses on I/O wiring.
}

component main = RootV1();
