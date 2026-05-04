pragma circom 2.1.6;


// Input 2 values using 'a'(array of length 2) and check if they thet are not equal using negation of IsZero().
// Return using signal 'c'.

include "../node_modules/circomlib/circuits/comparators.circom";

template NotEqual() {
   signal input a[2];
   signal tmp <== IsZero()(a[0] - a[1]);

   signal output c <== -1 * tmp + 1;
}


component main = NotEqual();