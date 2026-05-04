pragma circom 2.1.2;

include "../../../hash_functions/poseidon_semaphore/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

/**
    let's create a mock example of a full binary Merkle Tree with 4 levels (including the root level) 
    and demonstrate how you would derive the inputs (leaf, path indices, and siblings) for the MerkleTreeInclusionProof circuit. 

    ==> Full Merkle Tree Structure:

    Imagine a binary tree where each non-leaf node is the hash of its two children. 
    Let's define the leaf nodes as L1, L2, L3, ..., L8 (since there are 23=823=8 leaf nodes for a tree with 3 levels above the leaves).

    ==> Example Leaf and Path:

        - Chosen Leaf for Proof: Let's say we want to prove the inclusion of L3.
        - Path to Root: To reach the root from L3, the path goes left, right, left.

    ==> Deriving Path Indices:

        - Path indices are binary and indicate the direction taken at each level to reach the chosen leaf.
        - For L3, the path indices would be [0, 1, 0] (0 for left, 1 for right).

    ==> Deriving Sibling Nodes:

        - To compute the hash of the parent node at each level, you need the sibling of the node on the path.
        - For L3, the siblings would be:
            - At Level 1: Sibling of L3 is L4.
            - At Level 2: Sibling of the parent of L3 (which is the hash of L3 and L4) is the parent of L1 and L2 (the hash of L1 and L2).
            - At Level 3: Sibling of the parent node at Level 2 is the parent node of L5 to L8 (the hash of this subtree).

    ==> Mock Data for Testing:

        - Leaf Nodes: L1, L2, L3, ..., L8 (actual data values for leaves).
        - Chosen Leaf for Proof: L3.
        - Path Indices: [0, 1, 0].
        - Siblings:
            - Level 1 Sibling: L4.
            - Level 2 Sibling: Parent of L1 and L2.
            - Level 3 Sibling: Parent node of L5 to L8.

    ==> Using in Circuit:

    You would input L3 as the leaf, [0, 1, 0] as pathIndices, and the computed siblings into the circuit. The circuit would then generate a proof, and the resulting root should match the root of your predefined Merkle Tree if the proof is correct.

    This setup allows you to test the MerkleTreeInclusionProof circuit with specific, mock data, ensuring it behaves as expected for a known Merkle Tree structure and a chosen leaf.
*/

template MerkleTreeInclusionProof(nLevels) {
    signal input leaf;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];

    signal output root;

    component poseidon[nLevels];
    component mux[nLevels];

    signal hashes[nLevels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < nLevels; i++) {
        /**
            In the provided Circom circuit snippet, the line `pathIndices[i] * (1 - pathIndices[i]) === 0;` 
            serves a specific and crucial purpose. 
            It's a constraint to ensure that each element of the `pathIndices` array is either 0 or 1. Here's how it works:

            - `pathIndices` is an array of signals used in the context of a Merkle Tree inclusion proof. 
            Each element of this array represents a binary decision at each level of the tree: 
            whether to go left (0) or right (1) in the path from the leaf to the root.

            - The expression `pathIndices[i] * (1 - pathIndices[i])` will only equal zero if `pathIndices[i]` is either 0 or 1. This is because:
            - If `pathIndices[i]` is 0, then `1 - pathIndices[i]` is 1, and the product is 0.
            - If `pathIndices[i]` is 1, then `1 - pathIndices[i]` is 0, and again, the product is 0.
            - For any other value of `pathIndices[i]`, the product will not be zero.

            - The constraint `=== 0` ensures that during the proving process, 
            the only valid solutions for `pathIndices[i]` are 0 or 1. If any `pathIndices[i]` is not 0 or 1, 
            the constraint will fail, and the proof will be invalid.

            In cryptographic circuits like this, constraints are used to enforce certain conditions or rules. 
            In this case, the rule is that each index in the path must be a binary decision, 
            aligning with the binary nature of the paths in a Merkle Tree.
        */
        pathIndices[i] * (1 - pathIndices[i]) === 0; 

        poseidon[i] = PoseidonSemaphore();
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== siblings[i];

        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== hashes[i];

        mux[i].s <== pathIndices[i];

        poseidon[i].inputs[0] <== mux[i].out[0];
        poseidon[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== poseidon[i].out;
    }

    root <== hashes[nLevels];
}