pragma circom 2.0.0;

// ============================================================================
// NATIVE WHILE LOOP APPROACH IN CIRCOM
// 
// This circuit implements loop logic using native while loop syntax:
// - Uses var declarations for mutable variables
// - Demonstrates native while loop constraint generation
// - Shows how vars can be used in while loop constructs
// ============================================================================

template WhileLoopApproach() {
    signal input arr[5];  // Input array of 5 elements
    signal output sum;    // Output sum
    
    // Use native while loop with vars
    var temp_sum = 0;
    var i = 0;
    
    while (i < 5) {
        temp_sum = temp_sum + arr[i];
        i = i + 1;
    }
    
    sum <== temp_sum;
}

component main { public [arr] } = WhileLoopApproach();
