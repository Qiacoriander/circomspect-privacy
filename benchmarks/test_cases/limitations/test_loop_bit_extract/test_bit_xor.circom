template TestBitXor() {
    signal input in;
    signal output out;

    var sum = 0;
    for (var i = 0; i < 8; i++) {
        // Pattern: (in ^ (1 << i))
        // XOR with bit mask - should leak 1 bit per iteration
        sum += (in ^ (1 << i)); 
    }
    out <== sum;
}

component main = TestBitXor();
