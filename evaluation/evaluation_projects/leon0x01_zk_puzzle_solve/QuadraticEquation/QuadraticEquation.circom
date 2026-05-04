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

    signal ans1 <== x**2;
    signal ans2 <== a*ans1; 

    signal ans3 <== b*x;
    signal ans4 <== ans2 + ans3; 
    signal ans5 <== ans4 + c;

    component inz = IsEqual();
    inz.in[1] <== ans5;
    inz.in[0] <== res;
    out <== inz.out;
    
}

component main  = QuadraticEquation();



