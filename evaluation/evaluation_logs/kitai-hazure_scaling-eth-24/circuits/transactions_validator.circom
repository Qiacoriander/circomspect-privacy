pragma circom 2.1.3;

include "../node_modules/circomlib/circuits/comparators.circom";

template TransactionsValidator() {
    // Private input signals
    signal input in;
    // Output signal (public)
    signal output out;
    
    component gte;
    gte= GreaterEqThan(5);
    gte.in[0] <== in;
    gte.in[1] <== 2;

    gte.out === 1;
    out <== gte.out;
}

component main = TransactionsValidator();
