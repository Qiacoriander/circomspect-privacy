pragma circom 2.0.0;

// Include core primitives
include "../primitives/range_proof_lib.circom";
include "../primitives/hash_chain_lib.circom";

/*
 * StatsAggregator - Aggregate statistical measures with privacy preservation
 * 
 * This circuit proves:
 * 1. Weighted statistical measures (mean, variance)
 * 2. Privacy-preserving aggregation with differential privacy
 * 3. Robust statistics resistant to outliers
 * 4. Confidence intervals for estimates
 * 5. Distribution analysis of contributions
 */
template StatsAggregator(N) {
    // Input signals
    signal input values[N];                       // Raw values to aggregate
    signal input weights[N];                      // Weights for each value
    signal input privacyEpsilon;                  // Differential privacy parameter
    signal input sensitivityBound;               // Sensitivity bound for DP
    signal input confidenceLevel;                // Confidence level (e.g., 95)
    signal input outlierThreshold;               // Threshold for outlier detection
    signal input minValue;                       // Minimum expected value
    signal input maxValue;                       // Maximum expected value
    
    // Output signals
    signal output mean;                          // Weighted mean
    signal output variance;                      // Weighted variance
    signal output noisySum;                      // DP-noisy sum
    signal output noisyCount;                    // DP-noisy count
    signal output confidenceInterval[2];         // [lower_bound, upper_bound]
    signal output outlierCount;                  // Number of detected outliers
    signal output distributionSkew;              // Skewness measure
    signal output robustMean;                    // Outlier-resistant mean
    
    // Internal signals
    signal weightedValues[N];                    // values[i] * weights[i]
    signal totalWeight;                          // Sum of all weights
    signal outlierFlags[N];                      // 1 if value is outlier, 0 otherwise
    signal robustWeights[N];                     // Weights excluding outliers
    signal deviations[N];                        // Deviations from mean
    signal squaredDeviations[N];                 // Squared deviations
    signal noisyValues[N];                       // Privacy-noisy values
    
    // Components for statistical analysis
    component meanCalc = WeightedMean(N);
    component varianceCalc = WeightedVariance(N);
    component outlierDetector = OutlierDetector(N);
    component robustMeanCalc = RobustMean(N);
    component confidenceCalc = ConfidenceInterval(N);
    component skewnessCalc = SkewnessCalculator(N);
    component privacyEngine = DifferentialPrivacy(N);
    
    // Range proofs for input validation
    component valueRanges[N];
    component weightRanges[N];
    
    // Hash chain for integrity
    component dataChain = HashChain(N);
    
    // Validate input ranges
    for (var i = 0; i < N; i++) {
        valueRanges[i] = RangeProofCustom(32);
        valueRanges[i].value <== values[i];
        valueRanges[i].min <== minValue;
        valueRanges[i].max <== maxValue;
        valueRanges[i].valid === 1;
        
        weightRanges[i] = RangeProofCustom(16);
        weightRanges[i].value <== weights[i];
        weightRanges[i].min <== 0;
        weightRanges[i].max <== 1000; // Max reasonable weight
        weightRanges[i].valid === 1;
    }
    
    // Calculate weighted values and total weight
    component totalWeightCalc = Sum(N);
    component weightedValueCalcs[N];
    for (var i = 0; i < N; i++) {
        weightedValueCalcs[i] = Multiplier();
        weightedValueCalcs[i].in[0] <== values[i];
        weightedValueCalcs[i].in[1] <== weights[i];
        weightedValues[i] <== weightedValueCalcs[i].out;
        
        totalWeightCalc.values[i] <== weights[i];
    }
    totalWeight <== totalWeightCalc.out;
    
    // Calculate weighted mean
    for (var i = 0; i < N; i++) {
        meanCalc.values[i] <== values[i];
        meanCalc.weights[i] <== weights[i];
    }
    meanCalc.totalWeight <== totalWeight;
    mean <== meanCalc.result;
    
    // Detect outliers
    for (var i = 0; i < N; i++) {
        outlierDetector.values[i] <== values[i];
        outlierDetector.weights[i] <== weights[i];
    }
    outlierDetector.mean <== mean;
    outlierDetector.threshold <== outlierThreshold;
    
    // Count outliers
    component outlierCounter = Sum(N);
    for (var i = 0; i < N; i++) {
        outlierFlags[i] <== outlierDetector.isOutlier[i];
        outlierCounter.values[i] <== outlierFlags[i];
    }
    outlierCount <== outlierCounter.out;
    
    // Calculate robust weights (excluding outliers)
    component robustWeightCalcs[N];
    for (var i = 0; i < N; i++) {
        robustWeightCalcs[i] = Multiplier();
        robustWeightCalcs[i].in[0] <== weights[i];
        robustWeightCalcs[i].in[1] <== 1 - outlierFlags[i]; // 0 if outlier, weight if not
        robustWeights[i] <== robustWeightCalcs[i].out;
    }
    
    // Calculate robust mean (excluding outliers)
    for (var i = 0; i < N; i++) {
        robustMeanCalc.values[i] <== values[i];
        robustMeanCalc.weights[i] <== robustWeights[i];
    }
    robustMean <== robustMeanCalc.result;
    
    // Calculate deviations and squared deviations
    component deviationCalcs[N];
    component squaredDeviationCalcs[N];
    for (var i = 0; i < N; i++) {
        deviationCalcs[i] = SafeSubtraction();
        deviationCalcs[i].a <== values[i];
        deviationCalcs[i].b <== mean;
        deviations[i] <== deviationCalcs[i].result;
        
        squaredDeviationCalcs[i] = Multiplier();
        squaredDeviationCalcs[i].in[0] <== deviations[i];
        squaredDeviationCalcs[i].in[1] <== deviations[i];
        squaredDeviations[i] <== squaredDeviationCalcs[i].out;
    }
    
    // Calculate weighted variance
    for (var i = 0; i < N; i++) {
        varianceCalc.values[i] <== values[i];
        varianceCalc.weights[i] <== weights[i];
        varianceCalc.squaredDeviations[i] <== squaredDeviations[i];
    }
    varianceCalc.mean <== mean;
    varianceCalc.totalWeight <== totalWeight;
    variance <== varianceCalc.result;
    
    // Calculate skewness
    for (var i = 0; i < N; i++) {
        skewnessCalc.values[i] <== values[i];
        skewnessCalc.weights[i] <== weights[i];
        skewnessCalc.deviations[i] <== deviations[i];
    }
    skewnessCalc.mean <== mean;
    skewnessCalc.variance <== variance;
    distributionSkew <== skewnessCalc.skewness;
    
    // Apply differential privacy
    for (var i = 0; i < N; i++) {
        privacyEngine.values[i] <== values[i];
        privacyEngine.weights[i] <== weights[i];
    }
    privacyEngine.epsilon <== privacyEpsilon;
    privacyEngine.sensitivity <== sensitivityBound;
    noisySum <== privacyEngine.noisySum;
    noisyCount <== privacyEngine.noisyCount;
    
    // Calculate confidence interval
    for (var i = 0; i < N; i++) {
        confidenceCalc.values[i] <== values[i];
        confidenceCalc.weights[i] <== weights[i];
    }
    confidenceCalc.mean <== mean;
    confidenceCalc.variance <== variance;
    confidenceCalc.confidenceLevel <== confidenceLevel;
    confidenceInterval[0] <== confidenceCalc.lowerBound;
    confidenceInterval[1] <== confidenceCalc.upperBound;
    
    // Build integrity hash chain
    dataChain.startHash <== 1; // Default start hash
    dataChain.finalHash <== mean + variance; // Computed final hash
    for (var i = 0; i < N; i++) {
        dataChain.values[i] <== values[i] + weights[i]; // Combined hash
    }
    
    // Output validation constraints
    component meanRange = RangeProofCustom(32);
    meanRange.value <== mean;
    meanRange.min <== minValue;
    meanRange.max <== maxValue;
    meanRange.valid === 1;
    
    component varianceRange = RangeProofCustom(32);
    varianceRange.value <== variance;
    varianceRange.min <== 0;
    varianceRange.max <== (maxValue - minValue) * (maxValue - minValue);
    varianceRange.valid === 1;
    
    // Constraint: Total weight must be positive
    component positiveWeight = GreaterThan(32);
    positiveWeight.in[0] <== totalWeight;
    positiveWeight.in[1] <== 0;
    positiveWeight.out === 1;
    
    // Constraint: Outlier count must be reasonable
    component reasonableOutliers = LessThan(16);
    reasonableOutliers.in[0] <== outlierCount;
    reasonableOutliers.in[1] <== N / 2; // Less than half should be outliers
    reasonableOutliers.out === 1;
}

/*
 * Helper template: Calculate weighted mean
 */
template WeightedMean(N) {
    signal input values[N];
    signal input weights[N];
    signal input totalWeight;
    signal output result;
    
    // Calculate weighted sum
    signal weightedSum;
    component sumCalc = Sum(N);
    component weightedValues[N];
    for (var i = 0; i < N; i++) {
        weightedValues[i] = Multiplier();
        weightedValues[i].in[0] <== values[i];
        weightedValues[i].in[1] <== weights[i];
        sumCalc.values[i] <== weightedValues[i].out;
    }
    weightedSum <== sumCalc.out;
    
    // Calculate mean
    component meanCalc = SafeDivision(32);
    meanCalc.dividend <== weightedSum;
    meanCalc.divisor <== totalWeight;
    result <== meanCalc.quotient;
}

/*
 * Helper template: Calculate weighted variance
 */
template WeightedVariance(N) {
    signal input values[N];
    signal input weights[N];
    signal input squaredDeviations[N];
    signal input mean;
    signal input totalWeight;
    signal output result;
    
    // Calculate weighted sum of squared deviations
    signal weightedSumSquares;
    component sumSquaresCalc = Sum(N);
    component weightedSquares[N];
    for (var i = 0; i < N; i++) {
        weightedSquares[i] = Multiplier();
        weightedSquares[i].in[0] <== squaredDeviations[i];
        weightedSquares[i].in[1] <== weights[i];
        sumSquaresCalc.values[i] <== weightedSquares[i].out;
    }
    weightedSumSquares <== sumSquaresCalc.out;
    
    // Calculate variance
    component varianceCalc = SafeDivision(32);
    varianceCalc.dividend <== weightedSumSquares;
    varianceCalc.divisor <== totalWeight;
    result <== varianceCalc.quotient;
}

/*
 * Helper template: Detect outliers using statistical methods
 */
template OutlierDetector(N) {
    signal input values[N];
    signal input weights[N];
    signal input mean;
    signal input threshold;
    signal output isOutlier[N];
    
    // Detect outliers based on deviation from mean
    component deviations[N];
    component absDeviations[N];
    component outlierChecks[N];
    for (var i = 0; i < N; i++) {
        deviations[i] = SafeSubtraction();
        deviations[i].a <== values[i];
        deviations[i].b <== mean;
        
        absDeviations[i] = AbsoluteValue();
        absDeviations[i].in <== deviations[i].result;
        
        outlierChecks[i] = GreaterThan(32);
        outlierChecks[i].in[0] <== absDeviations[i].out;
        outlierChecks[i].in[1] <== threshold;
        isOutlier[i] <== outlierChecks[i].out;
    }
}

/*
 * Helper template: Calculate robust mean (outlier-resistant)
 */
template RobustMean(N) {
    signal input values[N];
    signal input weights[N];
    signal output result;
    
    // Calculate weighted mean with robust weights
    signal weightedSum;
    signal totalWeight;
    
    component sumCalc = Sum(N);
    component weightCalc = Sum(N);
    component weightedValues[N];
    
    for (var i = 0; i < N; i++) {
        weightedValues[i] = Multiplier();
        weightedValues[i].in[0] <== values[i];
        weightedValues[i].in[1] <== weights[i];
        sumCalc.values[i] <== weightedValues[i].out;
        weightCalc.values[i] <== weights[i];
    }
    
    weightedSum <== sumCalc.out;
    totalWeight <== weightCalc.out;
    
    component meanCalc = SafeDivision(32);
    meanCalc.dividend <== weightedSum;
    meanCalc.divisor <== totalWeight + 1; // Avoid division by zero
    result <== meanCalc.quotient;
}

/*
 * Helper template: Calculate confidence interval
 */
template ConfidenceInterval(N) {
    signal input values[N];
    signal input weights[N];
    signal input mean;
    signal input variance;
    signal input confidenceLevel;
    signal output lowerBound;
    signal output upperBound;
    
    // Calculate standard error
    signal standardError;
    component sqrtCalc = SquareRoot();
    sqrtCalc.in <== variance;
    standardError <== sqrtCalc.out;
    
    // Calculate margin of error (simplified)
    signal marginOfError;
    component marginCalc = Multiplier();
    marginCalc.in[0] <== standardError;
    marginCalc.in[1] <== 196; // Approximation for 95% confidence (1.96 * 100)
    component marginDiv = SafeDivision(32);
    marginDiv.dividend <== marginCalc.out;
    marginDiv.divisor <== 100;
    marginOfError <== marginDiv.quotient;
    
    // Calculate bounds
    component lowerCalc = SafeSubtraction();
    lowerCalc.a <== mean;
    lowerCalc.b <== marginOfError;
    lowerBound <== lowerCalc.result;
    
    component upperCalc = SafeAddition();
    upperCalc.a <== mean;
    upperCalc.b <== marginOfError;
    upperBound <== upperCalc.result;
}

/*
 * Helper template: Calculate skewness
 */
template SkewnessCalculator(N) {
    signal input values[N];
    signal input weights[N];
    signal input deviations[N];
    signal input mean;
    signal input variance;
    signal output skewness;
    
    // Calculate third moment (simplified)
    signal thirdMoment;
    component thirdMomentCalc = Sum(N);
    component cubedDeviations[N];
    component weightedCubes[N];
    
    for (var i = 0; i < N; i++) {
        cubedDeviations[i] = Multiplier();
        cubedDeviations[i].in[0] <== deviations[i] * deviations[i];
        cubedDeviations[i].in[1] <== deviations[i];
        
        weightedCubes[i] = Multiplier();
        weightedCubes[i].in[0] <== cubedDeviations[i].out;
        weightedCubes[i].in[1] <== weights[i];
        thirdMomentCalc.values[i] <== weightedCubes[i].out;
    }
    thirdMoment <== thirdMomentCalc.out;
    
    // Calculate skewness (simplified)
    component skewnessCalc = SafeDivision(32);
    skewnessCalc.dividend <== thirdMoment;
    skewnessCalc.divisor <== variance * variance + 1; // Avoid division by zero
    skewness <== skewnessCalc.quotient;
}

/*
 * Helper template: Apply differential privacy
 */
template DifferentialPrivacy(N) {
    signal input values[N];
    signal input weights[N];
    signal input epsilon;
    signal input sensitivity;
    signal output noisySum;
    signal output noisyCount;
    
    // Calculate true sum
    signal trueSum;
    component sumCalc = Sum(N);
    component weightedValues[N];
    for (var i = 0; i < N; i++) {
        weightedValues[i] = Multiplier();
        weightedValues[i].in[0] <== values[i];
        weightedValues[i].in[1] <== weights[i];
        sumCalc.values[i] <== weightedValues[i].out;
    }
    trueSum <== sumCalc.out;
    
    // Calculate true count
    signal trueCount;
    component countCalc = Sum(N);
    for (var i = 0; i < N; i++) {
        countCalc.values[i] <== weights[i];
    }
    trueCount <== countCalc.out;
    
    // Add Laplace noise (simplified - use deterministic noise for circuit)
    component noiseSum = LaplaceNoise();
    noiseSum.epsilon <== epsilon;
    noiseSum.sensitivity <== sensitivity;
    noisySum <== trueSum + noiseSum.noise;
    
    component noiseCount = LaplaceNoise();
    noiseCount.epsilon <== epsilon;
    noiseCount.sensitivity <== 1;
    noisyCount <== trueCount + noiseCount.noise;
}

component main = StatsAggregator(10); 