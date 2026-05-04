pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

// Hash left and right inputs using Poseidon.
// template HashLR() {
//     signal input L;
//     signal input R;
//     signal output out;

//     component hasher = Poseidon(2);
//     hasher.inputs[0] <== L;
//     hasher.inputs[1] <== R;

//     hasher.out ==> out;
// }

// template HashSingle() {
//     signal input single;
//     signal output out;

//     component hasher = Poseidon(1);
//     hasher.inputs[0] <== single;

//     hasher.out ==> out;
// }

// Hash using MiMC7.
template HashLR() {
    signal input L;
    signal input R;
    signal output out;

    // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
    component hasher = MultiMiMC7(2, 91);
    hasher.in[0] <== L;
    hasher.in[1] <== R;
    // Give hasher a fixed key of 1.
    hasher.k <== 1;
    out <== hasher.out;
}

template HashSingle() {
    signal input single;
    signal output out;

    // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
    component hasher = MiMC7(91);
    hasher.x_in <== single;
    // Give hasher a fixed key of 1.
    hasher.k <== 1;
    out <== hasher.out;
}

// Flow 
// strategist submits proof to AVS operators offchain
// AVS operators verify the proof offchain, as well as that the inputs are good
// AVS operators sign some message
// message allows strategist to submit rebalance onchain.

// TODO change this so that it accepts multiple leafs as private inputs.
// Then add a new public input which is a keccak256 hash of all the leafs.
// Then the circuit verifies that when it hashes down all the private leafs into a single hash, that hash
// matches the public hash.
// Then avs operators can be given all the info they need to verify the proof offchain,
// as well as checking a couple things like the secret leaf hash, root, and nonce match the ones in the contract.
// 

// TODO this needs to accept multiple leafs as private inputs, and accept a new public leaf digest hash
// TODO add nonce logic to this so that each batch of proofs will have different proofs.
// TODO as more proofs are added this circuit will get bigger and add to verification time, so it might be better to 
// try and optimize by storing the last two bits of each leaf in one signal, then we constrain the amount of leafs per proof to be less than 128. 
template VedaMerkleProof(LEVELS) {
    
    // Public signals
    signal input leafInTwo[2];
    signal input secretLeafHash; // Used to constrain leafInTwo to NOT be the secret leaf.
    signal input rootWithSecret;

    // Private signals
    signal input pathElements[LEVELS];
    signal input pathIndices[LEVELS];

    // Internal signals.
    signal leaf;

    component hashers[LEVELS + 1];
    component switchers[LEVELS];
    component secretCheckHasher = HashSingle();
    component eqs = IsEqual();

    // Hash leafInTwo to leaf.
    hashers[0] = HashLR();
    hashers[0].L <== leafInTwo[0];
    hashers[0].R <== leafInTwo[1];

    leaf <== hashers[0].out;

    // Constrain leaf to not be the secret leaf.
    secretCheckHasher.single <== leaf;
    eqs.in[0] <== secretCheckHasher.out;
    eqs.in[1] <== secretLeafHash;
    // Constrain leaf to not equal secret leaf.
    eqs.out === 0;

    for (var i=0; i<LEVELS; i++) {
        // Setup switchers.
        switchers[i] = Switcher();
        switchers[i].L <== hashers[i].out;
        switchers[i].R <== pathElements[i];
        switchers[i].sel <== pathIndices[i];

        // Setup hashers.
        hashers[i+1] = HashLR();
        hashers[i+1].L <== switchers[i].outL;
        hashers[i+1].R <== switchers[i].outR;
    }

    // Check that the root is correct.
    rootWithSecret === hashers[LEVELS].out;
}

template VedaMerkleProofN(LEVELS, N) {
    // Public signals
    signal input leafInTwo[2][N];
    signal input secretLeafHash[N]; // Used to constrain leafInTwo to NOT be the secret leaf.
    signal input rootWithSecret[N];

    // Private signals
    signal input pathElements[LEVELS][N];
    signal input pathIndices[LEVELS][N];

    // Create N instances of VedaMerkleProof.
    component provers[N];
    for (var i=0; i<N; i++) {
        provers[i] = VedaMerkleProof(LEVELS);
        provers[i].leafInTwo[0] <== leafInTwo[0][i];
        provers[i].leafInTwo[1] <== leafInTwo[1][i];
        provers[i].secretLeafHash <== secretLeafHash[i];
        provers[i].rootWithSecret <== rootWithSecret[i];
        for (var j=0; j<LEVELS; j++) {
            provers[i].pathElements[j] <== pathElements[j][i];
            provers[i].pathIndices[j] <== pathIndices[j][i];

        }
    }
}

// component main {public [leafInTwo, secretLeafHash, rootWithSecret]} = VedaMerkleProofN(2, 10);
component main {public [leafInTwo, secretLeafHash, rootWithSecret]} = VedaMerkleProof(2);