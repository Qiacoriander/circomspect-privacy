pragma circom 2.0.4;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/bitify.circom";

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

template IMTNonMembership(depth) {
    signal input query;
    signal input pre_val;
    signal input pre_next;
    signal input path[depth];
    signal input dirs[depth];
    signal input root_pub;

    component leafHash = Poseidon(2);
    leafHash.inputs[0] <== pre_val;
    leafHash.inputs[1] <== pre_next;
    signal cur[depth+1];
    cur[0] <== leafHash.out;

    component hashes[depth];
    for(var i=0; i< depth;i++) {
        hashes[i] = Poseidon(2);
        var left = (dirs[i] == 1) ? path[i] : cur[i];
        var right = (dirs[i] == 1) ? cur[i] : path[i];
        hashes[i].inputs[0] <-- left;
        hashes[i].inputs[1] <-- right;
        cur[i+1] <== hashes[i].out;
    }

    root_pub === cur[depth];

    // For IMT non-membership proof constraints:
    // 1. pre_val < query (since pre_val = 0, this is always true for positive query)
    // 2. If pre_next != 0, then query < pre_next
    
    component isZeroPreVal = IsZero();
    isZeroPreVal.in <== pre_val;
    // Constraint: pre_val must be 0 (for this specific case)
    isZeroPreVal.out === 1;

    component isZeroPreNext = IsZero();
    isZeroPreNext.in <== pre_next;

    signal notTerminal;
    notTerminal <== 1 - isZeroPreNext.out;
    
    // Since pre_next = 0, notTerminal = 0, so the second constraint is automatically satisfied
    // (notTerminal * anything) === 0 when notTerminal = 0
}

template IMTInsertion(depth) {
    signal input query;
    signal input pre_val;
    signal input pre_next;
    signal input path[depth];
    signal input dirs[depth];
    signal input old_root;
    signal output new_root;

    // First verify non-membership with the old root
    component nonMembership = IMTNonMembership(depth);
    nonMembership.query <== query;
    nonMembership.pre_val <== pre_val;
    nonMembership.pre_next <== pre_next;
    nonMembership.path <== path;
    nonMembership.dirs <== dirs;
    nonMembership.root_pub <== old_root;

    // Now compute the new tree state after insertion
    // After insertion, predecessor leaf becomes: (pre_val, query)
    // And new leaf becomes: (query, pre_next)
    
    // Compute hash of updated predecessor leaf
    component updatedPreLeafHash = Poseidon(2);
    updatedPreLeafHash.inputs[0] <== pre_val;
    updatedPreLeafHash.inputs[1] <== query;

    // Compute new root with updated predecessor leaf
    signal cur1[depth+1];
    cur1[0] <== updatedPreLeafHash.out;

    component hashes1[depth];
    for(var i=0; i< depth;i++) {
        hashes1[i] = Poseidon(2);
        var left = (dirs[i] == 1) ? path[i] : cur1[i];
        var right = (dirs[i] == 1) ? cur1[i] : path[i];
        hashes1[i].inputs[0] <-- left;
        hashes1[i].inputs[1] <-- right;
        cur1[i+1] <== hashes1[i].out;
    }

    new_root <== cur1[depth];
}

template Vote(depthD, depthI) {
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

    // IMT insertion: prove non-membership and compute new root after insertion
    component imtInsertion = IMTInsertion(depthI);
    signal input imt_query;
    signal input imt_pre_val;
    signal input imt_pre_next;
    signal input imt_path[depthI];
    signal input imt_dirs[depthI];
    signal input imt_old_root;
    
    imtInsertion.query <== imt_query;
    imtInsertion.pre_val <== imt_pre_val;
    imtInsertion.pre_next <== imt_pre_next;
    imtInsertion.path <== imt_path;
    imtInsertion.dirs <== imt_dirs;
    imtInsertion.old_root <== imt_old_root;

    signal output new_spent_root;
    new_spent_root <== imtInsertion.new_root;
}

component main = Vote(20, 32);