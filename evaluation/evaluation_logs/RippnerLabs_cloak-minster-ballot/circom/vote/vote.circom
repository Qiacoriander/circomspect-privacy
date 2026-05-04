pragma circom 2.0.4;

include "./node_modules/circomlib/circuits/poseidon.circom";

template SparseNonMembership(depth) {
    signal input key;
    signal input spent_path[depth];
    signal input spent_siblings[depth];
    signal input curr_root;
    signal output new_root;

    // First pass: verify non-membership (value should be 0 at this key position)
    var curr = 0;
    component h_nonmember[depth];
    for(var i = 0; i < depth; i++){
        var is_right = spent_path[i];
        var l = (is_right) * spent_siblings[i] + (1-is_right) * curr;
        var r = (is_right) * curr + (1-is_right) * spent_siblings[i];

        h_nonmember[i] = Poseidon(2);
        h_nonmember[i].inputs[0] <-- l;
        h_nonmember[i].inputs[1] <-- r;
        curr = h_nonmember[i].out;
    }

    // Verify that the computed root matches the current spent tree root
    curr_root === curr;

    // Second pass: compute new root after setting this key to 1 (marking as spent)
    curr = 1;
    component h_member[depth];
    for(var i = 0; i < depth; i++) {
        var is_right = spent_path[i];
        var l2 = (is_right) * spent_siblings[i] + (1-is_right) * curr;
        var r2 = (is_right) * curr + (1-is_right) * spent_siblings[i];
        
        h_member[i] = Poseidon(2);
        h_member[i].inputs[0] <-- l2;
        h_member[i].inputs[1] <-- r2;
        curr = h_member[i].out;
    }

    new_root <== curr;
}

template Vote(depthD, depthS) {
    signal input identity_nullifier;
    signal input membership_merke_tree_siblings[depthD];
    signal input membership_merke_tree_path_indices[depthD];

    signal leaf;
    leaf <== identity_nullifier;

    signal cur[depthD+1];
    cur[0] <== leaf;

    var is_right;
    var left;
    var right;
    component cur_node[depthD];
    for(var i=0; i < depthD; i++) {
        is_right = membership_merke_tree_path_indices[i];
        left = (is_right) * membership_merke_tree_siblings[i] + (1-is_right) * cur[i];
        right = (is_right) * cur[i] + (1-is_right) * membership_merke_tree_siblings[i];
        
        cur_node[i] = Poseidon(2);
        cur_node[i].inputs[0] <-- left;
        cur_node[i].inputs[1] <-- right;
        cur[i+1] <== cur_node[i].out;
    }

    signal output membership_merkle_root;
    membership_merkle_root <== cur[depthD];

    // spent leaves
    signal input spent_root;
    signal input spent_siblings[depthS];
    signal input spent_path[depthS];

    component spent_tree = SparseNonMembership(depthS);
    spent_tree.key <== identity_nullifier;
    spent_tree.spent_path <== spent_path;
    spent_tree.spent_siblings <== spent_siblings; 
    spent_tree.curr_root <== spent_root;

    signal output new_spent_root;
    new_spent_root <== spent_tree.new_root;
}

component main = Vote(20, 256);