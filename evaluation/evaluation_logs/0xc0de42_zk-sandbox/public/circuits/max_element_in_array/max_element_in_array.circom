pragma circom 2.1.8;
include "comparators.circom";

template MaxElementInArray(n) {
    assert (n > 0);
    signal input numbers[n];
    
    var max = 0;
    for (var i = 0; i < n; i++) {
        max = max > numbers[i]? max : numbers[i];
    }

    signal maxSignal <-- max;
    signal out;
    component isGreater[n];
    component EQ[n];

    var acc;
    for (var i = 0; i < n; i++) {
        isGreater[i] = GreaterEqThan(252);
        isGreater[i].in[0] <== maxSignal;
        isGreater[i].in[1] <== numbers[i];
        isGreater[i].out === 1;

        EQ[i] = IsEqual();
        EQ[i].in[0] <== maxSignal;
        EQ[i].in[1] <== numbers[i];
        acc += EQ[i].out;
    }
    component zero;
    zero = IsEqual();
    zero.in[0] <== acc;
    zero.in[1] <== 0;
    zero.out === 0;
    out <== maxSignal;
}

component main = MaxElementInArray(10);