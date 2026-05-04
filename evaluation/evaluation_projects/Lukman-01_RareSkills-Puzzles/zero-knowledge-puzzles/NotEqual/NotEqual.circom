pragma circom 2.1.4;
include "../node_modules/circomlib/circuits/comparators.circom";

// Input: a, an array of length 2.
// Output: c.
// In this exercise, you have to check that a[0] is NOT equal to a[1].
// If they are not equal, output 1; otherwise, output 0.

// HINT: NEGATION

template NotEqual() {

    // Define the input signal array 'a' with 2 elements
    signal input a[2];

    // Define the output signal 'c' which will store the result
    signal output c;

    // Instantiate the IsEqual component to compare the two values
    component eq = IsEqual();

    // Assign the first element of 'a' to eq's first input
    eq.in[0] <== a[0];

    // Assign the second element of 'a' to eq's second input
    eq.in[1] <== a[1];

    // The IsEqual component will output 1 if the two inputs are equal, otherwise 0.
    // We want 'c' to be 1 if they are NOT equal, so we negate the output of eq.
    // c = 1 - eq.out will give us the desired output:
    // If a[0] == a[1], eq.out = 1, so c = 1 - 1 = 0.
    // If a[0] != a[1], eq.out = 0, so c = 1 - 0 = 1.
    c <== 1 - eq.out;
}

// Instantiate the main component that will execute the NotEqual template
component main = NotEqual();
