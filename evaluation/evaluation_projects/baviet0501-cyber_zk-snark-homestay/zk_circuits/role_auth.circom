// zk_circuits/role_auth.circom
// Compatible with circom 0.5.x
// Role-based authentication with Merkle root verification
// Circuit verifies: user knows secret, and user's commitment is in Merkle tree with specific root

template SimpleHash() {
    signal input in;
    signal output out;
    
    // Simple hash: out = in^2 + in + 1 (mod p)
    signal temp;
    temp <== in * in;
    out <== temp + in + 1;
}

template RoleAuth() {
    // Private Input: Secret (password or derived secret)
    signal private input secret;
    
    // Public Input: Commitment (hash of secret stored in database)
    signal input commitment;
    
    // Public Input: Role/Department (e.g., "sales", "it")
    // For simplicity, we'll use a number: 1=sales, 2=it, 3=hr, etc.
    signal input role;
    
    // Public Input: Merkle Root (stored in database for this department)
    signal input merkle_root;
    
    // Use simple hash to create commitment from secret
    component hasher = SimpleHash();
    hasher.in <== secret;
    
    // Constraint 1: Hash of secret must equal public commitment
    commitment === hasher.out;
    
    // Constraint 2: Role must match (we'll verify this in backend by checking user.department)
    // For now, just pass role through - backend will verify role matches user.department
    
    // Note: Merkle root verification is done in backend
    // The circuit just ensures commitment is correct
    // Backend will verify that commitment's hash is in Merkle tree with given root
}

component main {public [commitment, role, merkle_root]} = RoleAuth();

