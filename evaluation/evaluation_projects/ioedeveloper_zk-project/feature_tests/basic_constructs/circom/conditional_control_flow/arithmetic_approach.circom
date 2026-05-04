pragma circom 2.0.0;

// ============================================================================
// ARITHMETIC CONDITIONAL CONTROL FLOW APPROACH
// 
// This circuit implements conditional logic using arithmetic constraints:
// - Multiplication and addition to encode conditional paths
// - All paths computed simultaneously
// - Explicit constraint generation
// ============================================================================

template ArithmeticConditionalControlFlow() {
    signal input a;
    signal input b;
    signal input condition;
    signal output out;
    
    // Arithmetic approach: use multiplication to select paths
    signal temp1;
    signal temp2;
    
    temp1 <== condition * (a + b);
    temp2 <== (1 - condition) * (a - b);
    
    // Output is the sum of both paths
    out <== temp1 + temp2;
}

component main { public [a, b, condition] } = ArithmeticConditionalControlFlow();
