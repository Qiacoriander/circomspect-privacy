include "circomlib/circuits/bitify.circom";
include "./utils/pedersen.circom";
include "commitment_hasher.circom";
include "hashTower.circom";

// Verifies that commitment that corresponds to given secret and nullifier is included in the merkle tree of deposits
template Withdraw() {
    signal input nullifierHash;
    signal input day;
    signal input recipient;  // not taking part in any computations
    signal input relayer;   // not taking part in any computations
    signal input relayerFee;    // not taking part in any computations
    signal input nullifier;
    signal input secret;
    signal input count;
    signal input dd;
    signal input D[127];
    signal input rootLv;
    signal input RL[4];
    signal input C[127 - 1][4];

    component hasher = CommitmentHasher();
    hasher.nullifier <== nullifier;
    hasher.secret <== secret;
    hasher.nullifierHash === nullifierHash;

    component leafHasher = MiMC5Sponge(2);
    leafHasher.ins[0] <== hasher.commitment;
    leafHasher.ins[1] <== day;
    leafHasher.k <== 0;
    signal leafHash <== leafHasher.o;

    component hashTower = HashTowerWithDigest(127, 4, 7, 3);
    

    hashTower.count <== count;
    hashTower.dd <== dd;
    for (var i = 0; i < 127; i++) {
        hashTower.D[i] <== D[i];
    }
    hashTower.rootLv <== rootLv;
    for (var i = 0; i < 4; i++) {
        hashTower.RL[i] <== RL[i];
    }
    for (var i = 0; i < 126; i++) {
        for (var j = 0; j < 4; j++) {
            hashTower.C[i][j] <== C[i][j];
        }
    }
    hashTower.leaf <== leafHash;

    // Add hidden signals to make sure that tampering with recipient or fee will invalidate the snark proof
    // Most likely it is not required, but it's better to stay on the safe side and it only takes 2 constraints
    // Squares are used to prevent optimizer from removing those constraints
    signal recipientSquare;
    recipientSquare <== recipient * recipient;
    signal relayerSquare;
    relayerSquare <== relayer * relayer;
    signal relayerFeeSquare;
    relayerFeeSquare <== relayerFee * relayerFee;
}

component main {public [dd, nullifierHash, day, recipient, relayer, relayerFee]} = Withdraw();
