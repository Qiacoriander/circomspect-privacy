pragma circom 2.0.8;

include "../sudoku/comparators.circom";

// A simple template to verify addition
template AdditionVerifier() {
    // Input: Two numbers to add and the claimed result
    signal input a;
    signal input b;
    signal input claimed_sum;
    
    // Compute the actual sum
    signal actual_sum;
    actual_sum <== a + b;
    
    // Verify the claimed sum matches the actual sum
    // This will fail the circuit if they don't match
    claimed_sum === actual_sum;
}

// Export the template
// component main = AdditionVerifier(); 