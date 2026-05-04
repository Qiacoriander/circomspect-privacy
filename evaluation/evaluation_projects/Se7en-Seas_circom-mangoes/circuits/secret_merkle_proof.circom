pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/mimc.circom";

template HashLeftRight() {
    signal input left;
    signal input right;
    signal output out;

    // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
    component hasher = MultiMiMC7(2, 91);
    hasher.in[0] <== left;
    hasher.in[1] <== right;
    // Give hasher a fixed key of 1.
    hasher.k <== 1;
    out <== hasher.out;
}

template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    // Constrain s to 0 or 1
    s * (1 - s) === 0;
    // Order in[0] and in[1] based on s
    // s == 0 => out[0] == in[0] and out[1] == in[1]
    // s == 1 => out[0] == in[1] and out[1] == in[0]
    out[0] <== (in[1] - in[0]) * s + in[0];
    out[1] <== (in[0] - in[1]) * s + in[1];
}

template SecretMerkleProof(LEVELS) {
    signal input secret;
    signal input keccakLeaf[2];
    signal input root;
    signal input pathElements[LEVELS];
    signal input pathIndices[LEVELS];

    // Internal signals.
    signal leaf;

    // Components.
    component keccakLeafHasher;
    component selectors[LEVELS];
    component hashers[LEVELS + 1];

    // Hash keccak leaf into leaf.
    keccakLeafHasher = HashLeftRight();
    keccakLeafHasher.left <== keccakLeaf[0];
    keccakLeafHasher.right <== keccakLeaf[1];
    leaf <== keccakLeafHasher.out;

    // Hash leaf with secret.
    hashers[0] = HashLeftRight();
    hashers[0].left <== leaf;
    hashers[0].right <== secret;

    for (var i =0; i < LEVELS; i++) {
        // Define DualMux
        selectors[i] = DualMux();
        selectors[i].in[0] <== hashers[i].out;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        // Define Hashers
        hashers[i + 1] = HashLeftRight();
        hashers[i + 1].left <== selectors[i].out[0];
        hashers[i + 1].right <== selectors[i].out[1];
    }

    // Constrain root to be the output of the last hasher
    root === hashers[LEVELS].out;
}

// By defaul all inputs are private.
component main {public [keccakLeaf, root]} = SecretMerkleProof(10);

