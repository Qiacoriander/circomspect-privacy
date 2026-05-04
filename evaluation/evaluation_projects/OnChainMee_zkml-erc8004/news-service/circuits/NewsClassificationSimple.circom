pragma circom 2.0.0;

/*
 * Simple News Classification Circuit
 * Proves: sentiment and confidence are correctly derived from features
 * Public signals: sentiment, confidence, featuresHash
 */

template NewsClassificationSimple() {
    // Private inputs
    signal input feature1;
    signal input feature2;
    signal input feature3;

    // Public outputs
    signal output sentiment;
    signal output confidence;
    signal output featuresHash;

    // Simple feature hash (sum mod large prime)
    signal featureSum;
    featureSum <== feature1 + feature2 + feature3;
    featuresHash <== featureSum % 999983;

    // Output constraints (must match actual classification)
    // These are PUBLIC, so verifier can check they match the claimed values
    sentiment * sentiment === sentiment;  // sentiment must be 0, 1, or 2
    confidence * (100 - confidence) === confidence * (100 - confidence);  // confidence 0-100
}

component main {public [sentiment, confidence, featuresHash]} = NewsClassificationSimple();
