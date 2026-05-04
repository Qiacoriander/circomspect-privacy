pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/comparators.circom";

// Create a circuit that is satisfied if `numerator`,
// `denominator`, `quotient`, and `remainder` represent
// a valid integer division. You will need a comparison check, so
// we've already imported the library and set n to be 252 bits.
//
// Hint: integer division in Circom is `\`.
// `/` is modular division
// `%` is integer modulus

template IntDiv(n) {
    signal input numerator;
    signal input denominator;
    signal input quotient;
    signal input remainder;

    // constrains
    // nq + r === d
    // d > 0
    // r < d
    // nq >= n
    // nq >= q

    // denominator > 0
    component isZero = IsZero();
    isZero.in <== denominator;
    isZero.out === 0;

    // remainder should be lesser than denominator
    component lt = LessThan(n);
    lt.in[0] <== denominator;
    lt.in[1] <== remainder;

    lt.out === 0;

    signal a <== quotient * denominator + remainder;

    component lte = LessEqThan(n);
    lte.in[0] <== quotient * denominator;
    lte.in[1] <== quotient;

    component lte_2 = LessEqThan(n);
    lte_2.in[0] <== quotient * denominator;
    lte_2.in[1] <== denominator;


}

component main = IntDiv(252);
