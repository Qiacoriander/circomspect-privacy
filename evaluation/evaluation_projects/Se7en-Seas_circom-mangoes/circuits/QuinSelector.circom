pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

template CalculateTotal(n) {
    signal input in[n];
    signal output out;

    signal sums[n];

    sums[0] <== in[0];

    for (var i = 1; i < n; i++) {
        sums[i] <== sums[i-1] + in[i];
    }

    out <== sums[n-1];
}

template QuinSelector(choices) {
    signal input in[choices];
    signal input index;
    signal output out;

    component lessThan = LessThan(4); // 4 is how many bits big the index and choices can be
    lessThan.in[0] <== index;
    lessThan.in[1] <== choices;
    // Constrain index to be less than choices.
    lessThan.out === 1;

    component calculateTotal = CalculateTotal(choices);
    component eqs[choices];

    for (var i=0; i < choices; i++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== index;
        eqs[i].in[1] <== i;

        // If index and i are equal, eqs.out is 1, otherwise 0.
        calculateTotal.in[i] <== eqs[i].out * in[i];
    }
    // Return 0 + 0 + ... + in[index]
    out <== calculateTotal.out;
}

// component main {public [index]} = QuinSelector(2);