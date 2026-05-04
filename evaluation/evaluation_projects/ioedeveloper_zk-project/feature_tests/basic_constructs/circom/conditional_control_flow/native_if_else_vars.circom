pragma circom 2.0.0;

// ============================================================================
// NATIVE IF-ELSE STATEMENTS WITH VARS APPROACH
// 
// This circuit implements conditional logic using native if-else statements:
// - Uses var declarations for mutable variables
// - Demonstrates native Circom control flow
// - Shows how vars can be used in conditional blocks
// ============================================================================

template NativeIfElseWithVars() {
    signal input a;
    signal input b;
    signal input condition;
    signal output out;
    
    // Use vars for mutable variables
    var x = 0;
    var y = 1;
    
    // Native if-else statement with vars
    if (condition >= 1) {
        x = a + b;
        y = x + 1;
    } else {
        y = a - b;
        x = y;
    }
    
    // Output the result
    out <== x + y;
}

component main { public [a, b, condition] } = NativeIfElseWithVars();
