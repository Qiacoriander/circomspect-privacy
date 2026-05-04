pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/comparators.circom";

template QuinSelector(n) {
    signal input in[n];
    signal input index;
    signal output out;

    // Quin Selector Pattern
    //
    // From array [a, b, c] if we want to select the element at index 0
    // [a. b, c] * [1, 0, 0] = a*1 + b*0 + c*0 = a
    //
    // If for example we want to select the element at index 1
    // [a, b, c] * [0, 1, 0] = a*0 + b*1 + c*0 = b
    //
    // If for example we want to select the element at index 2
    // [a, b, c] * [0, 0, 1] = a*0 + b*0 + c*1 = c

    component isEqs[n];
    signal intermediates[n];
    var sum;

    for (var i = 0; i < n; i++) {
        isEqs[i] = IsEqual();
        isEqs[i].in[0] <== i;
        isEqs[i].in[1] <== index;

        isEqs[i].out * in[i] ==> intermediates[i];
        sum += intermediates[i];
    }

    out <== sum;
}

template Swap(n) {
    signal input in[n];
    signal input i;
    signal input j;
    signal output out[n];

    component lti = LessEqThan(252);
    lti.in[0] <== i;
    lti.in[1] <== n;
    lti.out === 1;

    component ltj = LessEqThan(252);
    ltj.in[0] <== j;
    ltj.in[1] <== n;
    ltj.out === 1;

    component qsI = QuinSelector(n);
    component qsJ = QuinSelector(n);
    qsI.index <== i;
    qsJ.index <== j;

    for (var k = 0; k < n; k++) {
        qsI.in[k] <== in[k];
        qsJ.in[k] <== in[k];
    }

    component isEqsI[n];
    component isEqsJ[n];

    signal branches1[n];
    signal branches2[n];

    for (var idx = 0; idx < n; idx++) {
        isEqsI[idx] = IsEqual();
        isEqsI[idx].in[0] <== idx;
        isEqsI[idx].in[1] <== i;

        isEqsJ[idx] = IsEqual();
        isEqsJ[idx].in[0] <== idx;
        isEqsJ[idx].in[1] <== j;  

        branches1[idx] <== isEqsI[idx].out * qsJ.out;
        branches2[idx] <== isEqsJ[idx].out * qsI.out;

        out[idx] <== branches1[idx] + branches2[idx] + (1 - isEqsI[idx].out - isEqsJ[idx].out) * in[idx];
    }
}

component main = Swap(5);

