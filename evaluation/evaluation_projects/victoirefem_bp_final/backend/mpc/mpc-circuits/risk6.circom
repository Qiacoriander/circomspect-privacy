pragma circom 2.1.0;

include "./templates/WeightSum.circom";

template risk(n){
    signal input t;
    signal input ai[n];
    signal input ri[n];

    var alpha = 5;

    signal output fin;

    component sum = WeightSum(n);
    sum.ai <== ai;
    sum.ri <== ri;

    // fin <== alpha*sum.out/t;

    fin <== alpha*sum.out/t;

}

component main = risk(6);