pragma circom 2.1.8;
include "comparators.circom";


template MinElementInArray(n) {
    assert (n > 0);
    signal input numbers[n];

    var min = numbers[0];
    for (var i = 1; i < n; i++) {
        min = min < numbers[i] ? min : numbers[i];
    }

    signal minSignal <-- min;
    signal out;
    component isSmaller[n];
    component EQ[n];

    var acc;
    for (var i = 0; i < n; i++) {
        isSmaller[i] = LessEqThan(252);
        isSmaller[i].in[0] <== minSignal;
        isSmaller[i].in[1] <== numbers[i];
        isSmaller[i].out === 1;

        EQ[i] = IsEqual();
        EQ[i].in[0] <== minSignal;
        EQ[i].in[1] <== numbers[i];
        acc += EQ[i].out;
    }
    component zero;
    zero = IsEqual();
    zero.in[0] <== acc;
    zero.in[1] <== 0;
    zero.out === 0;
    out <== minSignal;
}

component main = MinElementInArray(10);
