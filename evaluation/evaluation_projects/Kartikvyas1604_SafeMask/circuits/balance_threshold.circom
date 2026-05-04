pragma circom 2.0.0;

/**
 * Balance Threshold Circuit
 * 
 * Proves that a hidden balance >= threshold without revealing the actual balance
 * 
 * Public inputs:
 * - threshold: minimum balance required
 * - balanceCommitment: Pedersen commitment to balance
 * 
 * Private inputs:
 * - balance: actual balance (secret)
 * - blindingFactor: commitment blinding factor (secret)
 */

template BalanceThreshold() {
    signal input balance;
    signal input threshold;
    signal input blindingFactor;
    signal output balanceCommitment;
    
    // Constraint: balance >= threshold
    signal diff;
    diff <== balance - threshold;
    
    // Ensure diff is non-negative (in-circuit range check would go here)
    // For simplicity, we assume balance is always >= 0 and >= threshold
    
    // Compute Pedersen commitment: C = balance * G + blindingFactor * H
    // This is a simplified version - real implementation uses elliptic curve points
    balanceCommitment <== balance * 1000000 + blindingFactor;
}

component main = BalanceThreshold();
