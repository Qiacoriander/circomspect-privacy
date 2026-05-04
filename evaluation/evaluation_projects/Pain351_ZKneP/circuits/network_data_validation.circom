pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom";

template NetworkDataValidation() {
    // Private inputs
    signal input nodeId;
    signal input dataHash;
    signal input accessLevel;
    signal input timestamp;
    
    // Public inputs
    signal input expectedDataHash;
    signal input minAccessLevel;
    signal input maxTimestamp;
    signal input securityLevel;
    
    // Public outputs
    signal output isValidAccess;
    signal output securityScore;
    
    // Data verification
    component dataCheck = IsEqual();
    dataCheck.in[0] <== dataHash;
    dataCheck.in[1] <== expectedDataHash;
    
    // Access level check
    component accessCheck = GreaterEqThan(8);
    accessCheck.in[0] <== accessLevel;
    accessCheck.in[1] <== minAccessLevel;
    
    // Time validation
    component timeCheck = LessEqThan(64);
    timeCheck.in[0] <== timestamp;
    timeCheck.in[1] <== maxTimestamp;
    
    component timeValidityCheck = GreaterThan(64);
    timeValidityCheck.in[0] <== timestamp;
    timeValidityCheck.in[1] <== maxTimestamp - 1800;
    
    signal timeValid <== timeCheck.out * timeValidityCheck.out;
    
    // Security level validation
    component level1 = IsEqual();
    level1.in[0] <== securityLevel;
    level1.in[1] <== 1;
    
    component level2 = IsEqual();
    level2.in[0] <== securityLevel;
    level2.in[1] <== 2;
    
    component level3 = IsEqual();
    level3.in[0] <== securityLevel;
    level3.in[1] <== 3;
    
    // FIXED: Split the quadratic constraints
    signal basicSecurity <== dataCheck.out * accessCheck.out;
    
    // Level 1: Basic security only
    signal security1 <== level1.out * basicSecurity;
    
    // Level 2: Basic + time (FIXED: Split into steps)
    signal securityWithTime <== basicSecurity * timeValid;
    signal security2 <== level2.out * securityWithTime;
    
    // Level 3: All validations
    signal security3 <== level3.out * securityWithTime;
    
    isValidAccess <== security1 + security2 + security3;
    
    // Security score
    signal validationCount <== dataCheck.out + accessCheck.out + timeValid;
    securityScore <== validationCount * 33;
}

component main = NetworkDataValidation();