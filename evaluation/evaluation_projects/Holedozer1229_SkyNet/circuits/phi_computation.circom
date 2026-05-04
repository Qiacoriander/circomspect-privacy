pragma circom 2.0.0;

/**
 * Φ Computation Circuit
 * Verifies the computation: Φ_total = Σ_i (w_i * φ_i) / N
 */
template PhiComputation(n) {
    signal input weights[n];
    signal input values[n];
    signal input eigenVectors[n];
    signal output phiTotal;
    signal output deltaSGeom;
    signal output deltaSProtocol;
    
    // Intermediate signals
    signal weightedSums[n];
    signal sqrtProducts[n];
    signal eigenSum;
    
    // Calculate weighted sums: w_i * φ_i
    var sum = 0;
    for (var i = 0; i < n; i++) {
        weightedSums[i] <== weights[i] * values[i];
        sum += weightedSums[i];
    }
    
    // Φ_total = Σ_i (w_i * φ_i) / N
    phiTotal <== sum / n;
    
    // Calculate ΔS_geom = Σ sqrt(w_i * φ_i)
    var geomSum = 0;
    for (var i = 0; i < n; i++) {
        // Simplified: use weighted product directly
        geomSum += weightedSums[i];
    }
    deltaSGeom <== geomSum;
    
    // Calculate ΔS_protocol = mean(eigenVectors)
    var eigenSumVar = 0;
    for (var i = 0; i < n; i++) {
        eigenSumVar += eigenVectors[i];
    }
    deltaSProtocol <== eigenSumVar / n;
}

/**
 * Main component with n=3 parameters
 */
component main {public [weights, values, eigenVectors]} = PhiComputation(3);
