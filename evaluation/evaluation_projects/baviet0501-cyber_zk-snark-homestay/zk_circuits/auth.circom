// zk_circuits/auth.circom
// Compatible with circom 0.5.x
// Authentication circuit using simple hash for commitment-based auth
// Due to circom 0.5.x limitations, we use a simplified hash approach

template SimpleHash() {
    signal input in;
    signal output out;
    
    // Simple hash: out = in^2 + in + 1 (mod p)
    // This is ZK-friendly and works with circom 0.5
    signal temp;
    temp <== in * in;
    out <== temp + in + 1;
}

template Auth() {
    // Private Input: Secret (password or derived secret)
    signal private input secret;
    
    // Public Input: Commitment (hash stored in database)
    signal input commitment;
    
    // Use simple hash to create commitment from secret
    component hasher = SimpleHash();
    hasher.in <== secret;
    
    // Constraint: Hash of secret must equal public commitment
    // If they don't match, proof generation will fail
    commitment === hasher.out;
}

component main = Auth();

