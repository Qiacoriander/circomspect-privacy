pragma circom 2.0.0;

// ============================================================================
// FOR LOOP APPROACH IN CIRCOM
// 
// This circuit implements loop logic using Circom's for loop:
// - Iterates through array elements using for loop
// - Accumulates sum of array elements
// - Demonstrates for loop constraint generation
// ============================================================================

template ForLoopApproach() {
    signal input arr[5];  // Input array of 5 elements
    signal output sum;    // Output sum
    
    // Use for loop to sum array elements
    var temp_sum = 0;
    for (var i = 0; i < 5; i++) {
        temp_sum = temp_sum + arr[i];
    }
    
    // Convert var to signal for output
    sum <== temp_sum;
}

component main { public [arr] } = ForLoopApproach();
