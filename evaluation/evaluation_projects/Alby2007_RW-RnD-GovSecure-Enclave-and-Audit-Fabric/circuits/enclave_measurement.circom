pragma circom 2.0.0;

/*
 * Enclave Measurement Circuit (Circom 2.x)
 * 
 * Proves that a job was executed in a specific enclave with a known measurement
 * without revealing the exact measurement value.
 * 
 * Public Inputs:
 *   - jobCount: Number of jobs to verify
 *   - enclaveType: Type of enclave (0=SGX, 1=SEV, 2=Nitro, 3=Simulation)
 * 
 * Private Inputs:
 *   - measurements[jobCount]: Array of enclave measurements (256-bit hashes)
 *   - expectedMeasurement: The expected measurement value
 * 
 * Output:
 *   - Proof that all jobs ran in enclaves with matching measurements
 */

include "../node_modules/circomlib/circuits/comparators.circom";

template EnclaveMeasurementVerifier(maxJobs) {
    // Public inputs
    signal input jobCount;
    signal input enclaveType;
    
    // Private inputs
    signal input measurements[maxJobs];
    signal input expectedMeasurement;
    
    // Output
    signal output valid;
    
    // Verify enclave type is valid (0-3)
    component enclaveTypeCheck = LessThan(3);
    enclaveTypeCheck.in[0] <== enclaveType;
    enclaveTypeCheck.in[1] <== 4;
    enclaveTypeCheck.out === 1;
    
    // Verify job count is within bounds
    component jobCountCheck = LessThan(32);
    jobCountCheck.in[0] <== jobCount;
    jobCountCheck.in[1] <== maxJobs + 1;
    jobCountCheck.out === 1;
    
    // Verify all measurements match expected measurement
    component measurementChecks[maxJobs];
    signal matchResults[maxJobs];
    
    for (var i = 0; i < maxJobs; i++) {
        measurementChecks[i] = IsEqual();
        measurementChecks[i].in[0] <== measurements[i];
        measurementChecks[i].in[1] <== expectedMeasurement;
        
        // If i < jobCount, measurement must match
        // If i >= jobCount, we don't care (padding)
        matchResults[i] <== measurementChecks[i].out;
    }
    
    // Sum all match results - should equal jobCount
    signal sum[maxJobs + 1];
    sum[0] <== 0;
    
    for (var i = 0; i < maxJobs; i++) {
        sum[i + 1] <== sum[i] + matchResults[i];
    }
    
    // Verify sum equals jobCount
    component sumCheck = IsEqual();
    sumCheck.in[0] <== sum[maxJobs];
    sumCheck.in[1] <== jobCount;
    
    // Output is valid if sum check passes
    valid <== sumCheck.out;
}

// Main component - supports up to 100 jobs
component main {public [jobCount, enclaveType]} = EnclaveMeasurementVerifier(100);
