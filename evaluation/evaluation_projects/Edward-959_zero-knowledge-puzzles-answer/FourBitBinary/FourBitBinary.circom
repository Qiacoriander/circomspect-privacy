pragma circom 2.1.8;

// Create a circuit that takes an array of four signals
// `in`and a signal s and returns is satisfied if `in`
// is the binary representation of `n`. For example:
// 
// Accept:
// 0,  [0,0,0,0]
// 1,  [1,0,0,0]
// 15, [1,1,1,1]
// 
// Reject:
// 0, [3,0,0,0]
// 
// The circuit is unsatisfiable if n > 15

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0; 
    // this serves as an accumulator to "recompute" in bit-by-bit
    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0; // force out[i] to be 1 or 0
        lc1 += out[i] * e2; //add to the accumulator if the bit is 1 
        e2 = e2+e2; // takes on values 1,2,4,8,...
    }

    lc1 === in;
}

template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0] + (1<<n) - in[1];

    out <== 1-n2b.out[n];
}

template FourBitBinary() {
    signal input in[4];
    signal input n;

    var mid;
    var temp;
    component ls0 = LessThan(16);
    component ls1 = LessThan(16);
    component ls2 = LessThan(16);
    component ls3 = LessThan(16);

    assert(n < 16);
    
    mid = n / (2**3);
    ls0.in[0] <== mid;
    ls0.in[1] <== 1;
    in[0] === 1 - ls0.out;
    in[0] * (1 - in[0]) === 0;

    mid = n / (2**2);
    ls1.in[0] <== mid;
    ls1.in[1] <== 1;
    in[1] === 1 - ls1.out;
    in[1] * (1 - in[1]) === 0;

    mid = n / (2**1);
    ls2.in[0] <== mid;
    ls2.in[1] <== 1;
    in[2] === 1 - ls2.out;
    in[2] * (1 - in[2]) === 0;

    mid = n / (2**0);
    ls3.in[0] <== mid;
    ls3.in[1] <== 1;
    in[3] === 1 - ls3.out;
    in[3] * (1 - in[3]) === 0;

}

component main{public [n]} = FourBitBinary();
