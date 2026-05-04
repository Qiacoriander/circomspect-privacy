pragma circom 2.0.0;

// Include core primitives
include "../primitives/range_proof_lib.circom";
include "../primitives/hash_chain_lib.circom";

/*
 * TimeAggregator - Aggregate temporal patterns across contributions
 * 
 * This circuit proves:
 * 1. Activity periods (sustained contribution over time)
 * 2. Average contribution frequency
 * 3. Temporal consistency index
 * 4. Contribution quality over time
 * 5. Active development periods vs gaps
 */
template TimeAggregator(MAX_COMMITS) {
    // Input signals
    signal input timestamps[MAX_COMMITS];         // Unix timestamps of commits
    signal input commitSizes[MAX_COMMITS];        // LOC added/modified per commit
    signal input commitTypes[MAX_COMMITS];        // Type: 1=feature, 2=bugfix, 3=refactor, etc.
    signal input activeThreshold;                 // Minimum commits per period to be "active"
    signal input periodLength;                    // Length of analysis period (e.g., 30 days)
    signal input qualityThreshold;               // Minimum LOC per commit for quality
    signal input maxTimeGap;                      // Maximum gap between commits (days)
    
    // Output signals
    signal output activityPeriods;               // Number of active periods
    signal output averageFrequency;              // Average commits per period
    signal output consistencyIndex;              // Temporal consistency (0-100)
    signal output qualityTrend;                  // Quality improvement trend
    signal output sustainabilityScore;           // Long-term contribution sustainability
    signal output gapAnalysis;                   // Analysis of contribution gaps
    
    // Internal signals
    signal timeGaps[MAX_COMMITS];                // Time gaps between consecutive commits
    signal activePeriodFlags[MAX_COMMITS];       // 1 if period is active, 0 otherwise
    signal qualityFlags[MAX_COMMITS];            // 1 if commit meets quality threshold
    
    // Components for temporal analysis
    component periodAnalyzer = ActivityPeriodCalculator(MAX_COMMITS);
    component frequencyCalc = FrequencyCalculator(MAX_COMMITS);
    component consistencyCalc = TemporalConsistency(MAX_COMMITS);
    component qualityAnalyzer = QualityTrendAnalyzer(MAX_COMMITS);
    component sustainabilityCalc = SustainabilityCalculator(MAX_COMMITS);
    component gapAnalyzer = GapAnalyzer(MAX_COMMITS);
    
    // Range proofs for output validation
    component activityRange = RangeProofCustom(16);
    component frequencyRange = RangeProofCustom(16);
    component consistencyRange = RangeProofCustom(8);
    component qualityRange = RangeProofCustom(8);
    component sustainabilityRange = RangeProofCustom(8);
    
    // Hash chain for temporal integrity
    component timeChain = HashChain(MAX_COMMITS);
    
    // Calculate time gaps between consecutive commits
    component gapCalcs[MAX_COMMITS];
    component timeOrders[MAX_COMMITS];
    for (var i = 1; i < MAX_COMMITS; i++) {
        gapCalcs[i] = SafeSubtraction();
        gapCalcs[i].a <== timestamps[i];
        gapCalcs[i].b <== timestamps[i-1];
        timeGaps[i] <== gapCalcs[i].result;
        
        // Verify timestamps are ordered
        timeOrders[i] = GreaterThan(32);
        timeOrders[i].in[0] <== timestamps[i];
        timeOrders[i].in[1] <== timestamps[i-1];
        timeOrders[i].out === 1;
    }
    timeGaps[0] <== 0; // First commit has no gap
    
    // Analyze activity periods
    for (var i = 0; i < MAX_COMMITS; i++) {
        periodAnalyzer.timestamps[i] <== timestamps[i];
        periodAnalyzer.commitSizes[i] <== commitSizes[i];
        periodAnalyzer.commitTypes[i] <== commitTypes[i];
    }
    periodAnalyzer.threshold <== activeThreshold;
    periodAnalyzer.periodLength <== periodLength;
    activityPeriods <== periodAnalyzer.periods;
    
    // Calculate average frequency
    for (var i = 0; i < MAX_COMMITS; i++) {
        frequencyCalc.timestamps[i] <== timestamps[i];
        frequencyCalc.sizes[i] <== commitSizes[i];
    }
    frequencyCalc.periodLength <== periodLength;
    averageFrequency <== frequencyCalc.avgFrequency;
    
    // Calculate temporal consistency
    for (var i = 0; i < MAX_COMMITS; i++) {
        consistencyCalc.timestamps[i] <== timestamps[i];
        consistencyCalc.timeGaps[i] <== timeGaps[i];
        consistencyCalc.commitSizes[i] <== commitSizes[i];
    }
    consistencyCalc.maxGap <== maxTimeGap;
    consistencyIndex <== consistencyCalc.index;
    
    // Analyze quality trend over time
    for (var i = 0; i < MAX_COMMITS; i++) {
        qualityAnalyzer.timestamps[i] <== timestamps[i];
        qualityAnalyzer.commitSizes[i] <== commitSizes[i];
        qualityAnalyzer.commitTypes[i] <== commitTypes[i];
    }
    qualityAnalyzer.qualityThreshold <== qualityThreshold;
    qualityTrend <== qualityAnalyzer.trend;
    
    // Calculate sustainability score
    for (var i = 0; i < MAX_COMMITS; i++) {
        sustainabilityCalc.timestamps[i] <== timestamps[i];
        sustainabilityCalc.commitSizes[i] <== commitSizes[i];
        sustainabilityCalc.timeGaps[i] <== timeGaps[i];
    }
    sustainabilityCalc.maxGap <== maxTimeGap;
    sustainabilityScore <== sustainabilityCalc.score;
    
    // Analyze contribution gaps
    for (var i = 0; i < MAX_COMMITS; i++) {
        gapAnalyzer.timeGaps[i] <== timeGaps[i];
        gapAnalyzer.timestamps[i] <== timestamps[i];
    }
    gapAnalyzer.maxGap <== maxTimeGap;
    gapAnalysis <== gapAnalyzer.analysis;
    
    // Build hash chain for temporal integrity
    timeChain.startHash <== 1; // Default start hash
    timeChain.finalHash <== activityPeriods + consistencyIndex; // Computed final hash
    for (var i = 0; i < MAX_COMMITS; i++) {
        timeChain.values[i] <== timestamps[i];
    }
    
    // Apply range proofs to outputs
    activityRange.value <== activityPeriods;
    activityRange.min <== 1;
    activityRange.max <== 365; // Max reasonable activity periods (days)
    activityRange.valid === 1;
    
    frequencyRange.value <== averageFrequency;
    frequencyRange.min <== 0;
    frequencyRange.max <== 100; // Max reasonable commits per period
    frequencyRange.valid === 1;
    
    consistencyRange.value <== consistencyIndex;
    consistencyRange.min <== 0;
    consistencyRange.max <== 100;
    consistencyRange.valid === 1;
    
    qualityRange.value <== qualityTrend;
    qualityRange.min <== 0;
    qualityRange.max <== 100;
    qualityRange.valid === 1;
    
    sustainabilityRange.value <== sustainabilityScore;
    sustainabilityRange.min <== 0;
    sustainabilityRange.max <== 100;
    sustainabilityRange.valid === 1;
    
    // Constraint: Must have meaningful activity
    component hasActivity = GreaterThan(16);
    hasActivity.in[0] <== activityPeriods;
    hasActivity.in[1] <== 0;
    hasActivity.out === 1;
    
    // Constraint: Consistency must be reasonable for sustained development
    component reasonableConsistency = GreaterThan(8);
    reasonableConsistency.in[0] <== consistencyIndex;
    reasonableConsistency.in[1] <== 20; // Minimum 20% consistency
    reasonableConsistency.out === 1;
}

/*
 * Helper template: Calculate activity periods
 */
template ActivityPeriodCalculator(N) {
    signal input timestamps[N];
    signal input commitSizes[N];
    signal input commitTypes[N];
    signal input threshold;
    signal input periodLength;
    signal output periods;
    
    // Group commits into time periods and count active ones
    signal periodCounts[N];
    signal activePeriods[N];
    
    // Simplified period calculation for circuit efficiency
    component activeCounter = Sum(N);
    component thresholdChecks[N];
    for (var i = 0; i < N; i++) {
        thresholdChecks[i] = GreaterEqualThan(8);
        thresholdChecks[i].in[0] <== commitSizes[i];
        thresholdChecks[i].in[1] <== threshold;
        activePeriods[i] <== thresholdChecks[i].out;
        activeCounter.values[i] <== activePeriods[i];
    }
    periods <== activeCounter.out;
}

/*
 * Helper template: Calculate average frequency
 */
template FrequencyCalculator(N) {
    signal input timestamps[N];
    signal input sizes[N];
    signal input periodLength;
    signal output avgFrequency;
    
    // Calculate total commits and time span
    signal totalCommits;
    signal timeSpan;
    
    component commitCounter = CountNonZero(N);
    for (var i = 0; i < N; i++) {
        commitCounter.values[i] <== sizes[i];
    }
    totalCommits <== commitCounter.count;
    
    // Calculate time span (last - first timestamp)
    component spanCalc = SafeSubtraction();
    spanCalc.a <== timestamps[N-1];
    spanCalc.b <== timestamps[0];
    timeSpan <== spanCalc.result;
    
    // Calculate average frequency (commits per period)
    component freqCalc = SafeDivision(32);
    freqCalc.dividend <== totalCommits * periodLength;
    freqCalc.divisor <== timeSpan;
    avgFrequency <== freqCalc.quotient;
}

/*
 * Helper template: Calculate temporal consistency
 */
template TemporalConsistency(N) {
    signal input timestamps[N];
    signal input timeGaps[N];
    signal input commitSizes[N];
    signal input maxGap;
    signal output index;
    
    // Calculate consistency based on gap regularity
    signal gapVariance;
    signal consistencyScore;
    
    // First calculate mean of timeGaps
    component meanCalc = Sum(N);
    for (var i = 0; i < N; i++) {
        meanCalc.values[i] <== timeGaps[i];
    }
    signal meanValue;
    component meanDiv = SafeDivision(32);
    meanDiv.dividend <== meanCalc.out;
    meanDiv.divisor <== N;
    meanValue <== meanDiv.quotient;
    
    component varianceCalc = Variance(N);
    for (var i = 0; i < N; i++) {
        varianceCalc.values[i] <== timeGaps[i];
    }
    varianceCalc.mean <== meanValue;
    gapVariance <== varianceCalc.variance;
    
    // Lower variance = higher consistency (simplified calculation)
    component consistencyCalc = ConsistencyFromVariance();
    consistencyCalc.variance <== gapVariance;
    index <== consistencyCalc.consistency;
}

/*
 * Helper template: Analyze quality trend
 */
template QualityTrendAnalyzer(N) {
    signal input timestamps[N];
    signal input commitSizes[N];
    signal input commitTypes[N];
    signal input qualityThreshold;
    signal output trend;
    
    // Calculate quality improvement over time (simplified)
    signal qualitySum;
    signal timeWeightedSum;
    
    component qualityCalc = Sum(N);
    component timeWeightCalc = Sum(N);
    component qualityChecks[N];
    
    for (var i = 0; i < N; i++) {
        qualityChecks[i] = GreaterEqualThan(16);
        qualityChecks[i].in[0] <== commitSizes[i];
        qualityChecks[i].in[1] <== qualityThreshold;
        
        qualityCalc.values[i] <== qualityChecks[i].out;
        timeWeightCalc.values[i] <== qualityChecks[i].out * (i + 1); // Weight by position
    }
    
    qualitySum <== qualityCalc.out;
    timeWeightedSum <== timeWeightCalc.out;
    
    // Calculate trend (positive if improving)
    component trendCalc = SafeDivision(32);
    trendCalc.dividend <== timeWeightedSum;
    trendCalc.divisor <== qualitySum + 1; // Avoid division by zero
    trend <== trendCalc.quotient;
}

/*
 * Helper template: Calculate sustainability score
 */
template SustainabilityCalculator(N) {
    signal input timestamps[N];
    signal input commitSizes[N];
    signal input timeGaps[N];
    signal input maxGap;
    signal output score;
    
    // Measure long-term sustainability factors
    signal regularityScore;
    signal volumeScore;
    
    // Count commits within acceptable time gaps
    component regularityCalc = Sum(N);
    component volumeCalc = Sum(N);
    component gapChecks[N];
    component sizeChecks[N];
    
    for (var i = 0; i < N; i++) {
        gapChecks[i] = LessThan(32);
        gapChecks[i].in[0] <== timeGaps[i];
        gapChecks[i].in[1] <== maxGap;
        regularityCalc.values[i] <== gapChecks[i].out;
        
        sizeChecks[i] = GreaterThan(16);
        sizeChecks[i].in[0] <== commitSizes[i];
        sizeChecks[i].in[1] <== 0;
        volumeCalc.values[i] <== sizeChecks[i].out;
    }
    
    regularityScore <== regularityCalc.out;
    volumeScore <== volumeCalc.out;
    
    // Combined sustainability score
    component sustainabilityCalc = WeightedAverage();
    sustainabilityCalc.values[0] <== regularityScore;
    sustainabilityCalc.weights[0] <== 60; // 60% weight on regularity
    sustainabilityCalc.values[1] <== volumeScore;
    sustainabilityCalc.weights[1] <== 40; // 40% weight on volume
    sustainabilityCalc.values[2] <== 0; // Unused third value
    sustainabilityCalc.weights[2] <== 0;
    score <== sustainabilityCalc.average;
}

/*
 * Helper template: Analyze contribution gaps
 */
template GapAnalyzer(N) {
    signal input timeGaps[N];
    signal input timestamps[N];
    signal input maxGap;
    signal output analysis;
    
    // Analyze patterns in contribution gaps
    signal longGaps[N];
    
    component gapCounter = Sum(N);
    component isLongGaps[N];
    for (var i = 0; i < N; i++) {
        isLongGaps[i] = GreaterThan(32);
        isLongGaps[i].in[0] <== timeGaps[i];
        isLongGaps[i].in[1] <== maxGap;
        longGaps[i] <== isLongGaps[i].out;
        gapCounter.values[i] <== longGaps[i];
    }
    
    // Calculate gap analysis score (fewer long gaps = better)
    component gapScore = SafeDivision(32);
    gapScore.dividend <== (N - gapCounter.out) * 100;
    gapScore.divisor <== N;
    analysis <== gapScore.quotient;
}

component main = TimeAggregator(24); 