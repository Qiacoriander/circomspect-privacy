// zk_circuits/password_check.circom
// Compatible with circom 0.5.x
// Simple circuit to verify password hash matches expected hash

template PasswordCheck() {
    // Private input: password hash (secret)
    signal private input passwordHash;
    
    // Public input: expected hash (from server)
    signal input expectedHash;
    
    // Public output: verification result
    signal output verified;
    
    // Constraint: passwordHash must equal expectedHash
    // This constraint ensures that passwordHash == expectedHash
    // If they don't match, the proof generation will fail
    passwordHash === expectedHash;
    
    // Output 1 to indicate verification passed
    verified <== 1;
}

component main = PasswordCheck();

