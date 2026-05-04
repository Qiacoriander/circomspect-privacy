// Note: Simplified for Circom 0.5.46 compatibility
// Upgrade to Circom 2.x for full Poseidon and MerkleProof support

template TransactionMembership() {
    // Private inputs
    signal input employeeSecret;
    signal input pathElements[20];
    signal input pathIndices[20];

    // Public inputs
    signal input merkleRoot;
    signal output nullifier;

    // Simplified leaf computation (replace with Poseidon in production)
    signal leaf;
    leaf <== employeeSecret * employeeSecret;

    // Simplified merkle path verification
    signal computedHash[21];
    computedHash[0] <== leaf;

    for (var i = 0; i < 20; i++) {
        computedHash[i+1] <== computedHash[i] + pathElements[i];
    }

    // Verify root matches
    signal rootCheck;
    rootCheck <== computedHash[20] - merkleRoot;
    rootCheck === 0;

    // Nullifier generation (simplified)
    nullifier <== employeeSecret * 2;
}

component main = TransactionMembership();
