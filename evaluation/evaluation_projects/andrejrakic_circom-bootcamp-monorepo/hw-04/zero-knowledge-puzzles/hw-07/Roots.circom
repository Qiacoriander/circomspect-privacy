pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/pointbits.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Inverse() {
    signal input in;
    signal output out;

    component isZero = IsZero();
    isZero.in <== in;
    isZero.out === 0;

    out <-- 1 / in;
}

//             ___________
//           \/ b^2 - 4ac
// x = -b ± ---------------
//                2a
//
template FindRoot() {
    signal input a;
    signal input b;
    signal input c;

    signal output root;

    var discriminant = sqrt(b * b - 4 * a * c);

    component inverse = Inverse();
    signal inv_2a;
    inverse.in <== 2 * a;
    inverse.out ==> inv_2a;

    root <-- (-b + discriminant) * inv_2a;
}

template Roots () {
    signal input a;
    signal input b;
    signal input c;

    signal output root;
    
    // implement function findRoot
    component findRoot = FindRoot();
    findRoot.a <== a;
    findRoot.b <== b;
    findRoot.c <== c;

    findRoot.root ==> root;

    signal a_root <== a * root;
    signal b_root <== b * root;

    // constraint
    0 === a_root * root + b_root + c;
}

component main = Roots();