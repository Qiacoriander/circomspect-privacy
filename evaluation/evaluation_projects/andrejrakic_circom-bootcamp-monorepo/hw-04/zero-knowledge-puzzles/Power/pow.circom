pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/comparators.circom";

// Create a circuit which takes an input 'a',(array of length 2 ) , then  implement power modulo 
// and return it using output 'c'.

// HINT: Non Quadratic constraints are not allowed.

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

template Pow(maxExponent) {
   signal input a[2]; // a[0] = base, a[1] = exponent
   signal output c;

    // LessEqThan returns 1 if in[0] <= in[1], otherwise 0
    component lt = LessEqThan(252);
    lt.in[0] <== a[1];
    lt.in[1] <== maxExponent;
    lt.out === 1;

    signal powers[maxExponent + 1];
    component qs = QuinSelector(maxExponent + 1);

    powers[0] <== 1; // x^0 = 1
    qs.in[0] <== powers[0];

    var i = 1;
    while (i <= maxExponent) {
        powers[i] <== powers[i - 1] * a[0]; 
        qs.in[i] <== powers[i];
        i++;
    }

    // c <== powers[a[1]]; Non-quadratic constraint was detected statically, using unknown index will cause the constraint to be non-quadratic

    qs.index <== a[1];
    qs.out ==> c;
}

component main = Pow(4);

