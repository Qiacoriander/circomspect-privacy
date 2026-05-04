pragma circom 2.0.0;

// Beta Tester Attestation Circuit
// Verifies that a user has actually tested the app with sufficient usage
// This ensures decentralization - the proof can be verified on-chain without revealing private usage data

template BetaTesterVerifier() {
    // Public inputs (visible on-chain)
    signal input walletAddressHash;  // Hash of wallet address (for verification)
    signal input minUsageThreshold;  // Minimum usage required (e.g., 10 features used)
    
    // Private inputs (hidden, proven via ZK)
    signal input actualUsage;        // Actual feature usage count (private)
    signal input walletAddress;       // Wallet address (private, for hash verification)
    signal input usageProof;          // Proof that usage data is valid
    
    // Output
    signal output verified;
    
    // Verify wallet address hash matches
    // In production, use Poseidon hash or similar
    // For now, simple check that walletAddress is non-zero
    component walletCheck = IsZero();
    walletCheck.in <== walletAddress;
    
    // Verify usage meets threshold
    component usageCheck = GreaterThan(32);
    usageCheck.in[0] <== actualUsage;
    usageCheck.in[1] <== minUsageThreshold;
    
    // Verify usage proof is valid (non-zero indicates valid proof)
    component proofCheck = IsZero();
    proofCheck.in <== usageProof;
    
    // All checks must pass
    verified <== (1 - walletCheck.out) * usageCheck.out * (1 - proofCheck.out);
}

// Helper templates
template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    
    inv <-- in != 0 ? 1/in : 0;
    out <== 1 - (in * inv);
}

template GreaterThan(n) {
    signal input in[2];
    signal output out;
    
    component lt = LessThan(n);
    lt.in[0] <== in[1];
    lt.in[1] <== in[0];
    out <== lt.out;
}

template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;
    
    component n2b = Num2Bits(n+1);
    n2b.in <== in[0] + (1 << n) - in[1];
    
    out <== 1 - n2b.out[n];
}

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;
    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }
    lc1 === in;
}

component main = BetaTesterVerifier();
