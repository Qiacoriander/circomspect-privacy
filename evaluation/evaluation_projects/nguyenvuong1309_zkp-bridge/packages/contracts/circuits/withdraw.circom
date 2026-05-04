pragma circom 2.0.0;

include "./merkleTree.circom";
include "./circomlib/circuits/comparators.circom";

// This circuit returns the sum of the inputs.
// n must be greater than 0.
template CalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for (var i=1; i < n; i++) {
        sums[i] <== sums[i - 1] + nums[i];
    }

    sum <== sums[n - 1];
}

template Withdraw(levels) {
    signal input root;

    // private
    signal input secret;
    signal input daoId;
    signal input path_elements[levels];
    signal input path_index[levels];

    // Generate commitment
    component preImage = CalculateTotal(2);
    component hasher = Poseidon(1);
    
    preImage.nums[0] <== daoId;
    preImage.nums[1] <== secret;

    hasher.inputs[0] <== preImage.sum;

    component tree = MerkleTree(levels);
    tree.leaf <== hasher.out;

    for (var i = 0; i < levels; i++) {
        tree.path_elements[i] <== path_elements[i];
        tree.path_index[i] <== path_index[i];
    }

    tree.root === root;
}


component main { public [root]} = Withdraw(4);