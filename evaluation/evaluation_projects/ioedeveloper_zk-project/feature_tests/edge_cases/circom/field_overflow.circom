pragma circom 2.0.0;

// ============================================================================
// FIELD OVERFLOW EDGE CASE TEST IN CIRCOM
// 
// This circuit tests how Circom handles field arithmetic overflow:
// - Tests operations near the bn128 curve prime field boundary
// - Prime p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// - Tests addition, multiplication, and subtraction near field limits
// - Demonstrates field arithmetic wrapping behavior
// ============================================================================

template FieldOverflow() {
    signal input a;
    signal input b;
    signal output result;
    
    // Test field arithmetic near the prime field boundary
    // The bn128 curve prime is very large, so we test operations that could overflow
    
    // Test addition near field boundary
    signal near_max;
    near_max <== 21888242871839275222246405745257275088548364400416034343698204186575808495616; // p-1
    
    // Test what happens when we add values near the field boundary
    signal overflow_test1;
    overflow_test1 <== near_max + a;
    
    // Test multiplication near field boundary
    signal overflow_test2;
    overflow_test2 <== near_max * b;
    
    // Test subtraction that could go below zero (wraps around)
    signal underflow_test;
    underflow_test <== a - b;
    
    // Test field arithmetic with large intermediate values
    signal large_intermediate;
    large_intermediate <== (near_max + 1) * (near_max - 1);
    
    // Combine all tests into a single result
    result <== overflow_test1 + overflow_test2 + underflow_test + large_intermediate;
}

// ============================================================================
// MAIN COMPONENT FOR TESTING
// ============================================================================

component main { public [a, b] } = FieldOverflow();
