pragma circom 2.0.0;

template TestConstantBound() {
    signal input in;
    signal output out;

    var sum = 0;
    var n = 8; // Constant variable used as loop bound
    for (var i = 0; i < n; i++) {
        sum += (in >> i) & 1;
    }
    
    out <== sum;
}

component main = TestConstantBound();
