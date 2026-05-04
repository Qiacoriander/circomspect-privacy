pragma circom 2.0.0;

/*
Sample Zero-Knowledge Proof Circuit for AIBPB
Proves that a value is within a specified range without revealing the actual value
*/

template RangeProof(n) {
    signal input value;
    signal input minValue;
    signal input maxValue;
    signal output valid;

    // Intermediate signals
    signal aboveMin;
    signal belowMax;
    
    // Check value >= minValue
    component gtMin = GreaterEqThan(n);
    gtMin.in[0] <== value;
    gtMin.in[1] <== minValue;
    aboveMin <== gtMin.out;
    
    // Check value <= maxValue
    component ltMax = LessEqThan(n);
    ltMax.in[0] <== value;
    ltMax.in[1] <== maxValue;
    belowMax <== ltMax.out;
    
    // Both conditions must be true
    valid <== aboveMin * belowMax;
    valid === 1;
}

// Comparison circuit for greater than or equal
template GreaterEqThan(n) {
    signal input in[2];
    signal output out;
    
    component lt = LessThan(n);
    lt.in[0] <== in[0];
    lt.in[1] <== in[1];
    
    out <== 1 - lt.out;
}

// Comparison circuit for less than or equal
template LessEqThan(n) {
    signal input in[2];
    signal output out;
    
    component gt = GreaterThan(n);
    gt.in[0] <== in[0];
    gt.in[1] <== in[1];
    
    out <== 1 - gt.out;
}

// Basic less than comparison
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;
    
    component n2b = Num2Bits(n+1);
    n2b.in <== in[0] + (1<<n) - in[1];
    
    out <== 1 - n2b.out[n];
}

// Basic greater than comparison
template GreaterThan(n) {
    signal input in[2];
    signal output out;
    
    component lt = LessThan(n);
    lt.in[0] <== in[1];
    lt.in[1] <== in[0];
    
    out <== lt.out;
}

// Number to bits converter
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc = 0;
    
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc = lc + out[i] * (1 << i);
    }
    
    lc === in;
}

// Main component
component main {public [minValue, maxValue]} = RangeProof(32);
