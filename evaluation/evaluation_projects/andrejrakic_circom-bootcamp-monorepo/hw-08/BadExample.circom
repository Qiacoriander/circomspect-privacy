pragma circom 2.1.8;

include "./node_modules/circomlib/circuits/comparators.circom";

template BadExample() {
    signal input num;
    signal input den;
    signal output quotient;
    signal output mod;

    quotient <-- num \ den;
    mod <-- num % den;

    num === den * quotient + mod;
    component iz = IsZero();
    iz.in <== den;
    iz.out === 0;
}

component main = BadExample();

/* INPUT = {
    "num": 10,
    "den": 3
}*/