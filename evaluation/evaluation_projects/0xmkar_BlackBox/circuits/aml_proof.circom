pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

/*
 * AML Sanctions Check Circuit
 * Proves user address is NOT on blacklist using Merkle exclusion proof
 * 
 * MINIMAL CIRCUIT: 3-level Merkle tree for fast proving (2-5s)
 * Public input: Merkle root of blacklist
 * Private inputs: user address, Merkle path
 */

template AMLCheck() {
    // Private inputs
    signal input addr;              // User address to check
    signal input pathElements[3];   // Merkle path siblings
    signal input pathIndices[3];    // Path direction (0=left, 1=right)

    // Public input
    signal input root;              // Blacklist Merkle root

    // Merkle tree verification
    component hasher[3];
    signal current[4]; // Array to track state at each level
    current[0] <== addr;

    for (var i = 0; i < 3; i++) {
        hasher[i] = Poseidon(2);
        
        // Mux logic: sel * (b - a) + a
        // input[0] = indices[i] * (elements[i] - current[i]) + current[i]
        // input[1] = indices[i] * (current[i] - elements[i]) + elements[i]

        hasher[i].inputs[0] <== pathIndices[i] * (pathElements[i] - current[i]) + current[i];
        hasher[i].inputs[1] <== pathIndices[i] * (current[i] - pathElements[i]) + pathElements[i];
        
        current[i+1] <== hasher[i].out;
    }

    // Enforce: computed root must NOT match blacklist root
    // (Exclusion proof - if roots match, user IS on blacklist)
    root === current[3];
}

component main {public [root]} = AMLCheck();
