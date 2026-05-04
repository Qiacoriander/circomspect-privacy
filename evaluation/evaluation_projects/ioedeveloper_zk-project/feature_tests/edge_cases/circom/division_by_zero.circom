pragma circom 2.0.0;

// ============================================================================
// DIVISION BY ZERO EDGE CASE TEST IN CIRCOM
// 
// This circuit tests how Circom handles division by zero:
// - Uses integer division with power operation: a \ (2**b)
// - Tests what happens when b causes division by zero
// - When b is very large, 2**b could cause edge cases
// ============================================================================

template DivisionByZero() {
    signal input a;
    signal input b;
    signal output result;
    
    // Division by power operation: a \ (2**b)
    // This tests division by zero when 2**b becomes problematic
    result <== a \ (2**b);
}

// ============================================================================
// MAIN COMPONENT FOR TESTING
// ============================================================================

component main { public [a, b] } = DivisionByZero();
