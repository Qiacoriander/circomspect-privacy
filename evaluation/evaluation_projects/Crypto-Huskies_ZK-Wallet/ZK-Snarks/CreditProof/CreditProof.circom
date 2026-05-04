pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template CreditProof() {
    signal input creditScore;
    signal input minCreditScore;
    signal input maxCreditScore;
    signal input address;
    signal input hash;

    // creditScore >= minCreditScore && creditScore <= maxCreditScore
    component lte = LessThan(252);
    lte.in[0] <== creditScore;
    lte.in[1] <== maxCreditScore;

    component gte = GreaterThan(252);
    gte.in[0] <== creditScore;
    gte.in[1] <== minCreditScore;

    lte.out * gte.out === 1;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== address;
    poseidon.inputs[1] <== creditScore;
    poseidon.out === hash;
    
}

component main {public [minCreditScore, maxCreditScore, address, hash]} = CreditProof();
