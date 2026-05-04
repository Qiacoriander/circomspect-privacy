pragma circom 2.1.8;

include "../node_modules/circomlib/comparators.circom";

template QuinSelector(n) {
    signal input in[n];
    signal input s;
    signal output out;

    component isEqs[n];
    signal intermediate[n];
    var sum;
    for (var i = 0; i < n; i++) {
        isEqs[i] = IsEqual();
        isEqs[i].in[0] <== i;
        isEqs[i].in[1] <== s;
        isEqs[i].out * in[i] ==> intermediate[i];
        sum += intermediate[i];
    }
    out <== sum;
}

template Factorial(n) {

    signal input x;
    signal output out;

    component lt = LessThan(252);
    lt.in[0] <== x;
    lt.in[1] <== n;
    lt.out === 1;

    signal fact[n + 1];
    fact[0] <== 1;
    fact[1] <== 1;

    for (var i = 2; i < n + 1; i++) {
        fact[i] <== fact[i - 1] * i;
    }
    

    component qs = QuinSelector(n);

    qs.s <== x;
    for (var i = 0; i < n; i++) {
        qs.in[i] <== fact[i];
    }

    out <== qs.out;
}


component main = Factorial(6);

/*
INPUT = {"x": 5}
*/