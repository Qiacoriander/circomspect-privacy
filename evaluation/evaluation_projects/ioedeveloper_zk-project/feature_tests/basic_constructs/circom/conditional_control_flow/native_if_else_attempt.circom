pragma circom 2.0.0;

// ============================================================================
// NATIVE IF-ELSE ATTEMPT IN CIRCOM
// 
// Note: Circom doesn't support native if-else for runtime conditional logic.
// This circuit demonstrates what happens when trying to use native constructs
// and shows the limitations of Circom for conditional control flow.
// ============================================================================

template NativeIfElseAttempt() {
    signal input a;
    signal input b;
    signal input condition;
    signal output out;

    signal temp;

    if (condition == 1) {
        temp <== a + b;
    } else {
        temp <== a - b;
    }
    
    out <== temp;
}

component main { public [a, b, condition] } = NativeIfElseAttempt();
