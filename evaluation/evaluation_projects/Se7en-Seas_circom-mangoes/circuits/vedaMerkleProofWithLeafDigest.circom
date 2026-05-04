pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mimc.circom";
include "vocdoni-keccak/keccak.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Hash left and right inputs using Poseidon.
template HashLR() {
    signal input L;
    signal input R;
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== L;
    hasher.inputs[1] <== R;

    hasher.out ==> out;
}

template HashSingle() {
    signal input single;
    signal output out;

    component hasher = Poseidon(1);
    hasher.inputs[0] <== single;

    hasher.out ==> out;
}

// Hash using MiMC7.
// template HashLR() {
//     signal input L;
//     signal input R;
//     signal output out;

//     // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
//     component hasher = MultiMiMC7(2, 91);
//     hasher.in[0] <== L;
//     hasher.in[1] <== R;
//     // Give hasher a fixed key of 1.
//     hasher.k <== 1;
//     out <== hasher.out;
// }

// template HashSingle() {
//     signal input single;
//     signal output out;

//     // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
//     component hasher = MiMC7(91);
//     hasher.x_in <== single;
//     // Give hasher a fixed key of 1.
//     hasher.k <== 1;
//     out <== hasher.out;
// }

template digestWithKeccak() {
    signal input bitsIn[256];
    signal input in[2];
    signal output out[256];

    // Define components.
    component inTo128Bits0 = Num2Bits(128);
    component inTo128Bits1 = Num2Bits(128);
    component keccak = Keccak(512, 256);

    // Convert in to 2 128 bit arrays.
    inTo128Bits0.in <== in[0];
    inTo128Bits1.in <== in[1];

    // Setup keccak.
    for (var i=0; i<128; i++) {
        keccak.in[2 * i] <== bitsIn[2 * i];
        keccak.in[2 * i + 1] <== bitsIn[2 * i + 1];
        keccak.in[i + 256] <== inTo128Bits0.out[i];
        keccak.in[i + 384] <== inTo128Bits1.out[i];
    }

    // Output keccak.
    for (var i=0; i<256; i++) {
        out[i] <== keccak.out[i];
    }

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
template VedaMerkleProofWithLeafDigest(LEVELS, N) {
    
    // Public signals
    signal input secretLeafHash; // Used to constrain leafInTwo to NOT be the secret leaf.
    signal input rootWithSecret;
    signal output leafDigest[2]; // keccak256 hash of all the private leafs.

    // Private signals
    signal input leafInTwo[2][N];
    signal input pathElements[LEVELS][N];
    signal input pathIndices[LEVELS][N];
    signal input secretBatchNonce; // First element digested in leafDigest, so that hash always changes even if leafs used are the same.
    signal input temp[LEVELS][N];
    
    // Internal signals.
    signal leaf[N];

    // Define components.
    component secretCheckHasher[N];
    component secretLeafEqs[N];
    component digestor[N];
    component nonceToBits = Num2Bits(256);
    component bitsToDigest[2];
    component hashers[LEVELS + 1][N];
    component switchers[LEVELS][N];
    
    // Hash leafInTwo to leaf.
    for (var i=0; i<N; i++) {
        hashers[0][i] = HashLR();
        hashers[0][i].L <== leafInTwo[0][i];
        hashers[0][i].R <== leafInTwo[1][i];
        leaf[i] <== hashers[0][i].out;
    }

    // Constrain leaf to not be the secret leaf.
    for (var i=0; i<N; i++){
        secretCheckHasher[i] = HashSingle();
        secretCheckHasher[i].single <== leaf[i];
        secretLeafEqs[i] = IsEqual();
        secretLeafEqs[i].in[0] <== secretCheckHasher[i].out;
        secretLeafEqs[i].in[1] <== secretLeafHash;
        // Constrain leaf to not equal secret leaf.
        secretLeafEqs[i].out === 0;
    }

    // Comput private leaf digest.
    digestor[0] = digestWithKeccak();
    nonceToBits.in <== secretBatchNonce;
    for (var i=0; i<256; i++) {
        digestor[0].bitsIn[i] <== nonceToBits.out[i];
    }
    digestor[0].in[0] <== leafInTwo[0][0];
    digestor[0].in[1] <== leafInTwo[1][0];
    for (var i=1; i<N; i++) {
        digestor[i] = digestWithKeccak();
        digestor[i].in[0] <== leafInTwo[0][i];
        digestor[i].in[1] <== leafInTwo[1][i];
        for (var j=0; j<256; j++) {
            digestor[i].bitsIn[j] <== digestor[i-1].out[j];
        }
    }
    // Convert final digestor output to 2 fields.
    bitsToDigest[0] = Bits2Num(128);
    bitsToDigest[1] = Bits2Num(128);
    for (var i=0; i<128; i++) {
        bitsToDigest[0].in[i] <== digestor[N-1].out[i];
        bitsToDigest[1].in[i] <== digestor[N-1].out[i+128];
    }
    // Constrain leafDigest to equal the digestor output.
    leafDigest[0] <== bitsToDigest[0].out;
    leafDigest[1] <== bitsToDigest[1].out ;


    // Check merkle proof.
    for (var j=0; j<N; j++) {
        for (var i=0; i<LEVELS; i++) {
            // Setup switchers.
            switchers[i][j] = Switcher();
            switchers[i][j].L <== hashers[i][j].out;
            switchers[i][j].R <== pathElements[i][j];
            switchers[i][j].sel <== pathIndices[i][j];
    
            // Setup hashers.
            hashers[i+1][j] = HashLR();
            hashers[i+1][j].L <== switchers[i][j].outL;
            hashers[i+1][j].R <== switchers[i][j].outR;
        }
    }

    // Check that the root is correct.
    for (var i=0; i<N; i++){
        rootWithSecret === hashers[LEVELS][i].out;
    }
}

// component main {public [leafInTwo, secretLeafHash, rootWithSecret]} = VedaMerkleProofN(2, 10);
component main {public [secretLeafHash, rootWithSecret]} = VedaMerkleProofWithLeafDigest(10, 12);