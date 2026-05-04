pragma circom 2.0.0;

/*
 * NewsClassification Circuit
 * Proves correct classification of news sentiment
 * WITHOUT revealing the actual features or headline
 */

template NewsClassification() {
    // Private inputs (not revealed on-chain)
    signal input feature1;  // Sentiment score (-1 to 1)
    signal input feature2;  // Key phrase indicator
    signal input feature3;  // Uncertainty indicator

    // Public outputs (revealed on-chain)
    signal output sentiment;      // 0=GOOD, 1=BAD, 2=NEUTRAL
    signal output confidence;     // 0-100
    signal output featuresHash;   // Hash of features for integrity

    // Intermediate signals
    signal sentimentScore;
    signal confidenceScore;
    signal featureSum;

    // Calculate feature sum for hashing
    featureSum <== feature1 + feature2 + feature3;

    // Simple hash: (f1*1000 + f2*100 + f3*10) mod 999983
    featuresHash <== (feature1 * 1000 + feature2 * 100 + feature3 * 10) % 999983;

    // Classification logic (simplified for circuit):
    // If feature1 > 0: GOOD (0)
    // If feature1 < 0: BAD (1)
    // If feature1 == 0: NEUTRAL (2)

    // Calculate sentiment (0, 1, or 2)
    component isPositive = GreaterThan(32);
    isPositive.in[0] <== feature1;
    isPositive.in[1] <== 0;

    component isNegative = LessThan(32);
    isNegative.in[0] <== feature1;
    isNegative.in[1] <== 0;

    // sentiment = isNegative * 1 + (1 - isPositive - isNegative) * 2
    sentiment <== isNegative.out + (1 - isPositive.out - isNegative.out) * 2;

    // Confidence = 60 + abs(feature1) * 20 (capped at 100)
    signal absFeature1;
    component abs = Abs();
    abs.in <== feature1;
    absFeature1 <== abs.out;

    confidenceScore <== 60 + absFeature1 * 20;

    // Cap confidence at 100
    component confCheck = LessThan(8);
    confCheck.in[0] <== confidenceScore;
    confCheck.in[1] <== 100;

    confidence <== confCheck.out * confidenceScore + (1 - confCheck.out) * 100;
}

// Helper: Compare if a > b
template GreaterThan(n) {
    signal input in[2];
    signal output out;

    component lt = LessThan(n);
    lt.in[0] <== in[1];
    lt.in[1] <== in[0];
    out <== lt.out;
}

// Helper: Compare if a < b
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n);
    n2b.in <== in[0] + (1<<n) - in[1];

    out <== 1-n2b.out[n-1];
}

// Helper: Absolute value
template Abs() {
    signal input in;
    signal output out;

    component isNeg = LessThan(32);
    isNeg.in[0] <== in;
    isNeg.in[1] <== 0;

    out <== isNeg.out * (-in) + (1 - isNeg.out) * in;
}

// Helper: Number to bits
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

component main = NewsClassification();
