pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/comparators.circom";

// Create a circuit that is satisfied if
// in[0] is the floor of the integer integer
// sqrt of in[1]. For example:
// 
// int[2, 5] accept
// int[2, 5] accept
// int[2, 9] reject
// int[3, 9] accept
//
// If b is the integer square root of a, then
// the following must be true:
//
// (b - 1)(b - 1) < a
// (b + 1)(b + 1) > a
// 
// be careful when verifying that you 
// handle the corner case of overflowing the 
// finite field. You should validate integer
// square roots, not modular square roots


template IntSqrt(n) {
    signal input in[2];

    signal lower_signal <== (in[0] - 1)*(in[0] - 1);
    signal upper_signal <== (in[0] + 1)*(in[0] + 1);

    component lt = LessThan(2 * n);
    lt.in[0] <== lower_signal;
    lt.in[1] <== in[1];

    component gt = GreaterThan(2 * n);
    gt.in[0] <== upper_signal;
    gt.in[1] <== in[1];

    lt.out * gt.out === 1;

}

component main = IntSqrt(252);
