pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template BudgetCheck(n) {
    signal input spends[n];
    signal input threshold;
    signal output result;

    // Calculate total spend using signals
    signal totalSpends[n];
    totalSpends[0] <== spends[0];
    
    for (var i = 1; i < n; i++) {
        totalSpends[i] <== totalSpends[i-1] + spends[i];
    }

    // Check if total spend is under threshold
    component isUnderBudget = LessThan(32);
    isUnderBudget.in[0] <== totalSpends[n-1];
    isUnderBudget.in[1] <== threshold;
    
    result <== isUnderBudget.out;
}

template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndex;
    signal output computedRoot;

    component poseidons[depth];
    component mux[depth];
    component mux2[depth];  // Declare all mux2 components at template level

    // Convert pathIndex to bits
    component indexBits = Num2Bits(depth);
    indexBits.in <== pathIndex;

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        poseidons[i] = Poseidon(2);
        mux[i] = Mux1();
        mux2[i] = Mux1();  // Initialize here instead of declaring

        // Select the order of inputs based on path bit
        mux[i].c[0] <== levelHashes[i];     // Current hash goes left if bit is 0
        mux[i].c[1] <== pathElements[i];    // Path element goes left if bit is 1
        mux[i].s <== indexBits.out[i];

        // Setup second mux for the right input
        mux2[i].c[0] <== pathElements[i];      // Path element goes right if bit is 0
        mux2[i].c[1] <== levelHashes[i];       // Current hash goes right if bit is 1
        mux2[i].s <== indexBits.out[i];

        poseidons[i].inputs[0] <== mux[i].out;
        poseidons[i].inputs[1] <== mux2[i].out;
        levelHashes[i + 1] <== poseidons[i].out;
    }

    computedRoot <== levelHashes[depth];
}

template BudgetMerkleCheckWithPrivacy(depth, n) {
    // Private inputs (default in Circom)
    signal input userIdHash;
    signal input spends[n];
    signal input pathElements[depth];
    signal input pathIndex;
    signal input spendsHash;  // Hash of the registered spends
    
    // Public inputs (explicitly marked)
    signal input threshold;
    signal input merkleRoot;
    
    // Output
    signal output result;

    // 1. Check budget constraint
    component budget = BudgetCheck(n);
    for (var i = 0; i < n; i++) {
        budget.spends[i] <== spends[i];
    }
    budget.threshold <== threshold;
    result <== budget.result;

    // 2. Verify spends integrity (user's spends match registered hash)
    component hasherSpends = Poseidon(n);
    for (var i = 0; i < n; i++) {
        hasherSpends.inputs[i] <== spends[i];
    }
    
    // Constraint: computed hash must equal the registered hash
    hasherSpends.out === spendsHash;

    // 3. Compute leaf hash for Merkle proof
    // leafHash = Poseidon(userIdHash, spendsHash)
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== userIdHash;
    leafHasher.inputs[1] <== spendsHash;

    // 4. Verify Merkle proof (user is in authorized set)
    component mp = MerkleProof(depth);
    mp.leaf <== leafHasher.out;
    for (var i = 0; i < depth; i++) {
        mp.pathElements[i] <== pathElements[i];
    }
    mp.pathIndex <== pathIndex;
    mp.computedRoot === merkleRoot;
}

component main = BudgetMerkleCheckWithPrivacy(10, 5);