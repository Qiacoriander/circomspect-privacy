pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/comparators.circom";

// In this exercise , we will learn how to check the range of a private variable and prove that 
// it is within the range . 

// For example we can prove that a certain person's income is within the range
// Declare 3 input signals `a`, `lowerbound` and `upperbound`.
// If 'a' is within the range, output 1 , else output 0 using 'out'


template Range() {
    // your code here
    signal input a;
    signal input lowerbound;
    signal input upperbound;
    signal output c;


    component lt = LessThan(252);
    component gt = GreaterThan(252);

    lt.in[0] <== a;
    lt.in[1] <== upperbound;

    gt.in[0] <== a;
    gt.in[1] <== lowerbound;


    c <== lt.out * gt.out;

}

component main  = Range();


