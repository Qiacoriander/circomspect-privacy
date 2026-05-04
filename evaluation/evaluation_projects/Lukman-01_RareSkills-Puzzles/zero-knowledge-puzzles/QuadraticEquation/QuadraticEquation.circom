pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/comparators.circom";

// Create a Quadratic Equation( ax^2 + bx + c ) verifier using the below data.
// Use comparators.circom lib to compare results if equal

template QuadraticEquation() {
    signal input x;     // x value
    signal input a;     // coefficient of x^2
    signal input b;     // coefficient of x 
    signal input c;     // constant c in equation
    signal input res;   // Expected result of the equation
    signal output out;  // If res is correct, return 1; else return 0.

    signal computedRes;  // Intermediate signal for the computed result

    // Compute ax^2 + bx + c
    computedRes <== a * x * x + b * x + c;

    // Comparator: Check if computed result equals the provided result
    component isEqual = IsEqual();

    isEqual.in[0] <== computedRes;
    isEqual.in[1] <== res;

    // Set the output based on the comparison
    out <== isEqual.out;
}

component main = QuadraticEquation();


