pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/comparators.circom";

// Be sure to solve IntSqrt before solving this 
// puzzle. Your goal is to compute the square root
// in the provided function, then constrain the answer
// to be true using your work from the previous puzzle.
// You can use the Bablyonian/Heron's or Newton's
// method to compute the integer square root. Remember,
// this is not the modular square root.



function intSqrtFloor(x) {
    // compute the floor of the
    // integer square root

    for(var i = 1; i<x; i++) {
        if ((i - 1) * (i - 1) < x && (i + 1) * (i + 1) > x) {
            return i;
        }
    }

    return 0;
    
}

template IntSqrtOut(n) {
    signal input in;
    signal output out;

    var x = in;

    out <-- intSqrtFloor(x);

    // constrain out using your
    // work from IntSqrt
    signal lower_signal <== (out - 1) * (out - 1);
    signal upper_signal <== (out + 1) * (out + 1);

    component lt = LessThan(n);
    lt.in[0] <== lower_signal;
    lt.in[1] <== in;

    component gt = GreaterThan(n);
    gt.in[0] <== upper_signal;
    gt.in[1] <== in;

    lt.out * gt.out === 1;
    
}

component main = IntSqrtOut(252);
