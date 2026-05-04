pragma circom 2.0.0;

include "../core/utilities.circom";

/*
 * DifferentialPrivacy adds calibrated noise to sensitive statistics
 * Implements ε-differential privacy for repository metrics
 */
template DifferentialPrivacy(precision) {
    signal input trueValue;
    signal input noiseValue; // Laplace noise scaled appropriately
    signal input epsilon; // Privacy parameter (scaled)
    signal input sensitivity; // Query sensitivity
    
    signal output noisyValue;
    signal output privacyBudget;
    signal output isValid;
    
    // Add noise to true value
    noisyValue <== trueValue + noiseValue;
    
    // Verify noise is appropriately calibrated for ε-DP
    component noiseCheck = NoiseCalibrationCheck(precision);
    noiseCheck.noiseValue <== noiseValue;
    noiseCheck.epsilon <== epsilon;
    noiseCheck.sensitivity <== sensitivity;
    
    privacyBudget <== epsilon;
    isValid <== noiseCheck.isValid;
}

/*
 * Noise calibration verification
 */
template NoiseCalibrationCheck(precision) {
    signal input noiseValue;
    signal input epsilon;
    signal input sensitivity;
    signal output isValid;
    
    // Expected noise scale = sensitivity / epsilon
    signal expectedScale;
    
    component divider = SafeDivision(precision);
    divider.dividend <== sensitivity;
    divider.divisor <== epsilon;
    expectedScale <== divider.quotient;
    
    // Check if noise is within reasonable bounds of expected scale
    component absNoise = AbsoluteValue();
    absNoise.in <== noiseValue;
    
    component upperBound = LessThan(precision);
    upperBound.in[0] <== absNoise.out;
    upperBound.in[1] <== expectedScale * 10; // Allow 10x scale for randomness
    
    component lowerBound = GreaterThan(precision);
    lowerBound.in[0] <== absNoise.out * 10;
    lowerBound.in[1] <== expectedScale;
    
    // Both bounds must be satisfied
    component andGate = AND();
    andGate.a <== upperBound.out;
    andGate.b <== lowerBound.out;
    isValid <== andGate.out;
}

/*
 * Note: KAnonymity is now implemented in ../privacy/k_anonymity.circom
 * Include that file to use advanced k-anonymity features
 */

/*
 * ComposedPrivacy handles composition of multiple DP queries
 */
template ComposedPrivacy(numQueries) {
    signal input epsilons[numQueries];
    signal input deltas[numQueries];
    signal output totalEpsilon;
    signal output totalDelta;
    signal output isValid;
    
    // Simple composition: sum epsilons and deltas
    signal runningEpsilon[numQueries + 1];
    signal runningDelta[numQueries + 1];
    
    runningEpsilon[0] <== 0;
    runningDelta[0] <== 0;
    
    for (var i = 0; i < numQueries; i++) {
        runningEpsilon[i + 1] <== runningEpsilon[i] + epsilons[i];
        runningDelta[i + 1] <== runningDelta[i] + deltas[i];
    }
    
    totalEpsilon <== runningEpsilon[numQueries];
    totalDelta <== runningDelta[numQueries];
    
    // Verify privacy budget doesn't exceed limits
    component epsilonCheck = LessThan(32);
    epsilonCheck.in[0] <== totalEpsilon;
    epsilonCheck.in[1] <== 10; // Max epsilon = 10 (scaled)
    
    isValid <== epsilonCheck.out;
}

// All utility templates are now included from utilities.circom

component main = DifferentialPrivacy(32);
