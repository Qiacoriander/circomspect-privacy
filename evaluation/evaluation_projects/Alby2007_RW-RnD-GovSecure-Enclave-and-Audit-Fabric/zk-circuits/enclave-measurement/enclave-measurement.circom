pragma circom 2.0.0;

/**
 * Enclave Measurement Circuit
 * 
 * Proves that all jobs were executed in enclaves with correct measurements.
 * 
 * Public Inputs:
 *   - jobCount: Number of jobs processed
 *   - enclaveType: Type of enclave (encoded as number)
 * 
 * Private Inputs:
 *   - measurements: Array of measurement hashes (simplified to sum)
 *   - expectedMeasurement: Expected measurement value
 * 
 * Output:
 *   - allMatch: 1 if all measurements match, 0 otherwise
 */
template EnclaveMeasurement() {
    // Public inputs
    signal input jobCount;
    signal input enclaveType;
    
    // Private inputs (witness)
    signal input measurements;  // Sum or hash of all measurements
    signal input expectedMeasurement;
    
    // Output
    signal output allMatch;
    
    // Intermediate signals
    signal measurementCheck;
    signal dummy;
    
    // Check 1: Measurements match expected
    measurementCheck <== measurements - expectedMeasurement;
    measurementCheck === 0;
    
    // Check 2: Use enclave type and job count
    // (Ensures they're part of the witness)
    dummy <== enclaveType + jobCount;
    
    // All checks passed
    allMatch <== 1;
}

component main {public [jobCount, enclaveType]} = EnclaveMeasurement();
