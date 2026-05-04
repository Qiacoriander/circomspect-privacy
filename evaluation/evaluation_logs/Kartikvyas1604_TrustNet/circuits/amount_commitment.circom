// Note: Using simplified commitment for Circom 0.5.46 compatibility
// In production, upgrade to Circom 2.x and use proper Poseidon hash

template AmountCommitment() {
    // 🔒 Private inputs (witness)
    signal input amount;
    signal input salt;

    // 🌍 Public output
    signal output commitment;

    // Simplified commitment (replace with Poseidon in production)
    signal temp;
    temp <== amount * salt;
    commitment <== temp + amount;
}

component main = AmountCommitment();
