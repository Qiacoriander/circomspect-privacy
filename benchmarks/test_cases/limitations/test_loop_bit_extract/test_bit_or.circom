template TestBitOr() {
    signal input in;
    signal output out;

    var sum = 0;
    for (var i = 0; i < 8; i++) {
        // Pattern: (in | (1 << i))
        // OR with bit mask - leaks information about cleared bits
        sum += (in | (1 << i)); 
    }
    out <== sum;
}

component main = TestBitOr();
