pragma circom 2.0.0;

template Loopy() {
    signal input in[5];
    signal output out;
    var sum = 0;
    for (var i = 0; i < 5; i++) {
        sum += in[i];
    }
    out <== sum;
}

component main = Loopy();
