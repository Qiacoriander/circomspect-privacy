pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/mimc.circom";
include "../node_modules/circomlib/circuits/comparators.circom";


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

// TODO optionally we could add a single input which is the MiMC hash of all the input data,
// Then all the leafs would be made secret, and there would be an extra step where the leafs are all hashed down, then the provided leaf hash is constrained to equal that hash.
// This is nice since it reduces the input amount to 2 inputs, but it means users would need to verify themselves that the hash matches the leafs.
// TODO what is interesting is we could maybe do the hash method above, but then in the contract we provide the function to hash an array of leafs down
// then people can submit stings to show that we provided the wrong hash?
// Could even make the hash be the merkle root if the leafs are not hashed with the secret? That way it is easier for people to verify the hash
// Since it is using a merkle setup.
// This circuit could even return the normal hash too.
template SecretdMerkleTree(LEAF_COUNT) {
    signal input secret; // Secret value hashed with leafs before tree construction.
    signal input keccakLeafs[2 * LEAF_COUNT]; // Each leaf is composed of 2 keccakLeafs where the first is the left 128 bits and the second is the right 128 bits.
    var arrayLength = 0;
    for (var i=0; 1 != LEAF_COUNT / (2 ** i); i++) {
        arrayLength += LEAF_COUNT / 2 ** (i + 1);
    }
    signal input pathIndices[arrayLength]; // Do not need pathIndices for the root.
    signal output secretRoot;

    // Internal signals.
    signal leafs[LEAF_COUNT];

    // Components.
    component keccakLeafHashers[LEAF_COUNT]; // Used to hash the keccak leafs into a single leaf.
    component selectors[arrayLength];
    component hashers[LEAF_COUNT + arrayLength]; // Add LEAF_COUNT to pre-hash every leaf with the secret.

    // Hash keccak leafs into leafs.
    for (var i=0; i<LEAF_COUNT; i++) {
        keccakLeafHashers[i] = HashLeftRight();
        keccakLeafHashers[i].left <== keccakLeafs[i * 2];
        keccakLeafHashers[i].right <== keccakLeafs[i * 2 + 1];
        leafs[i] <== keccakLeafHashers[i].out;
    }

    // Hash leafs with secret.
    for (var i=0; i<LEAF_COUNT; i++) {
        hashers[i] = HashLeftRight();
        hashers[i].left <== leafs[i]; // Left is always the leaf.
        hashers[i].right <== secret; // Right is always the secret.
    }

    var hasherOffset = LEAF_COUNT;
    var selectorOffset = 0;
    var hasherIndex = 0;

    // Hash internal digests.
    for (var i=0; 1 != LEAF_COUNT / (2 ** i); i++) {
        var iterations = LEAF_COUNT / (2 ** (i + 1));
        for (var j=0; j<iterations; j++) {
            selectors[j + selectorOffset] = DualMux();
            selectors[j + selectorOffset].in[0] <== hashers[hasherIndex].out;
            selectors[j + selectorOffset].in[1] <== hashers[hasherIndex + 1].out;
            selectors[j + selectorOffset].s <== pathIndices[j + selectorOffset];

            hashers[j + hasherOffset] = HashLeftRight();
            hashers[j + hasherOffset].left <== selectors[j + selectorOffset].out[0];
            hashers[j + hasherOffset].right <== selectors[j + selectorOffset].out[1];

            hasherIndex += 2;
        }
        hasherOffset += iterations;
        selectorOffset += iterations;
    }

    secretRoot <== hashers[hasherOffset - 1].out;
}

component main {public [keccakLeafs]} = SecretdMerkleTree(1024);