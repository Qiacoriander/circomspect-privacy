pragma circom 2.0.0;

template SumSquaresMod() {
    signal input a;
    signal input b;
    signal input q;
    signal output c;

    signal a2;
    signal b2;
    signal sum;
    signal tmp;

    var p = 23;

    // Cuadrados
    a2 <== a * a;
    b2 <== b * b;
    sum <== a2 + b2;

    // Multiplicación: tmp = q * p
    tmp <== q * p;

    // Resta: c = sum - tmp
    c <== sum - tmp;
}

component main = SumSquaresMod();

