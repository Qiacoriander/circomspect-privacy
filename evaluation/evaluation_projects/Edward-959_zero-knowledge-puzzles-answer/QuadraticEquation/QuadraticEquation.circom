pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/comparators.circom";

// Create a Quadratic Equation( ax^2 + bx + c ) verifier using the below data.
// Use comparators.circom lib to compare results if equal

template QuadraticEquation() {
    signal input x;     // x value
    signal input a;     // coeffecient of x^2
    signal input b;     // coeffecient of x 
    signal input c;     // constant c in equation
    signal input res;   // Expected result of the equation
    signal output out;  // If res is correct , then return 1 , else 0 . 

    signal temp1;
    signal temp2;
    signal temp3;
    signal temp4;
    temp1 <==  x * x;
    temp2 <== a * temp1;
    temp3 <== b * x;
    temp4 <== temp2 + temp3 + c;


    component isE = IsEqual();
    isE.in[0] <== temp4;
    isE.in[1] <== res;

    out <== isE.out;

    // your code here
}

component main  = QuadraticEquation();



