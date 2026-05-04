pragma circom 2.0.0;

// ============================================================================
// LOOP CONSTRAINT INFINITY EDGE CASE TEST IN CIRCOM
// 
// This circuit tests how Circom handles loops that generate:
// - Large numbers of constraints through iteration
// - Intermediate values that approach the prime field boundary
// - Accumulation operations that could overflow
// - Loop-based constraint generation near field limits
// ============================================================================

template LoopConstraintInfinity() {
    signal input a;
    signal input b;
    signal output result;
    
    // Use a loop to generate constraints and test field arithmetic
    // Avoid using var variables in signal assignments to maintain quadratic constraints
    
    // Create a very large array of signals for accumulation
    // This will generate a massive number of constraints
    signal accumulator[10000];
    signal multiplier[10000];
    
    // Initialize first values
    accumulator[0] <== a;
    multiplier[0] <== 1;
    
    // Loop that generates constraints for each iteration
    // This will create 10,000 constraints, testing Circom's constraint generation limits
    for (var i = 1; i < 10000; i++) {
        // Generate constraints for each step without using var in signal assignments
        multiplier[i] <== multiplier[i-1] * 2;
        multiplier[i] === multiplier[i-1] * 2;
        accumulator[i] <== accumulator[i-1] + (a * multiplier[i]);
        accumulator[i] === accumulator[i-1] + (a * multiplier[i]);
    }
    
    // Test multiplication with accumulated values (using signals, not vars)
    signal large_product;
    large_product <== accumulator[9999] * b;
    
    // Test addition with values near field boundary
    signal near_max;
    near_max <== 21888242871839275222246405745257275088548364400416034343698204186575808495616; // p-1
    
    // Combine loop result with field boundary operations
    result <== large_product + near_max + accumulator[9999];
}

// ============================================================================
// MAIN COMPONENT FOR TESTING
// ============================================================================

component main { public [a, b] } = LoopConstraintInfinity();
