pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/comparators.circom";

// Use the same constraints from IntDiv, but this
// time assign the quotient in `out`. You still need
// to apply the same constraints as IntDiv

template IntDivOut(n) {
    signal input numerator;
    signal input denominator;
    signal output out;

    // denominator > 0
    component isZero = IsZero();
    isZero.in <== denominator;
    isZero.out === 0;

    out <-- numerator \ denominator;

    signal remainder <-- numerator % out;
    numerator === out * denominator + remainder;

    // remainder should be lesser than denominator
    component lt = LessThan(n);
    lt.in[0] <== denominator;
    lt.in[1] <== remainder;
    lt.out === 0;

    component lte = LessEqThan(n);
    lte.in[0] <== out * denominator;
    lte.in[1] <== out;

    component lte_2 = LessEqThan(n);
    lte_2.in[0] <== out * denominator;
    lte_2.in[1] <== denominator;


}

component main = IntDivOut(252);
