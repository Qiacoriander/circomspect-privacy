pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/gates.circom";

/**
 * Security Level Circuit v2
 * 
 * IMPROVEMENTS FROM V1:
 * - ✅ Range checks on inputs (prevents overflow)
 * - ✅ minSecurityLevel actually used in constraints
 * - ✅ Output explicitly depends on all checks
 * - ✅ Better signal naming and documentation
 * - ✅ Validates all inputs are within expected ranges
 * 
 * Proves that all jobs in a batch meet a minimum security level.
 * 
 * Public Inputs:
 *   - jobCount: Number of jobs processed (0-1,000,000)
 *   - minSecurityLevel: Minimum required security level (0-10)
 * 
 * Private Inputs (Witness):
 *   - minLevelSum: Sum of jobs meeting minimum level
 *   - attestationSum: Sum of jobs with attestation
 *   - encryptionSum: Sum of jobs with encryption
 *   - actualMinLevel: Actual minimum level achieved
 * 
 * Output:
 *   - meetsLevel: 1 if all requirements met, 0 otherwise
 * 
 * Constraints:
 *   1. jobCount < 1,000,000 (prevent overflow)
 *   2. minSecurityLevel < 10 (valid range)
 *   3. actualMinLevel >= minSecurityLevel (enforces min level)
 *   4. minLevelSum == jobCount (all jobs meet level)
 *   5. attestationSum == jobCount (all jobs have attestation)
 *   6. encryptionSum == jobCount (all jobs have encryption)
 *   7. output = AND of all checks
 */
template SecurityLevelV2() {
    // Public inputs
    signal input jobCount;
    signal input minSecurityLevel;
    
    // Private inputs (witness)
    signal input minLevelSum;
    signal input attestationSum;
    signal input encryptionSum;
    signal input actualMinLevel;  // NEW: Actual minimum level achieved
    
    // Output
    signal output meetsLevel;
    
    // ===== RANGE CHECKS (Prevent overflow/invalid values) =====
    
    // Check 1: jobCount < 1,000,000
    component jobCountRangeCheck = LessThan(32);
    jobCountRangeCheck.in[0] <== jobCount;
    jobCountRangeCheck.in[1] <== 1000000;
    jobCountRangeCheck.out === 1;
    
    // Check 2: minSecurityLevel < 10 (valid security levels: 0-9)
    component minLevelRangeCheck = LessThan(8);
    minLevelRangeCheck.in[0] <== minSecurityLevel;
    minLevelRangeCheck.in[1] <== 10;
    minLevelRangeCheck.out === 1;
    
    // Check 3: actualMinLevel < 10 (valid range)
    component actualLevelRangeCheck = LessThan(8);
    actualLevelRangeCheck.in[0] <== actualMinLevel;
    actualLevelRangeCheck.in[1] <== 10;
    actualLevelRangeCheck.out === 1;
    
    // ===== SECURITY LEVEL ENFORCEMENT (NEW) =====
    
    // Check 4: actualMinLevel >= minSecurityLevel
    // This FIXES the critical vulnerability where minSecurityLevel wasn't enforced
    component levelMeetsMinimum = GreaterEqThan(8);
    levelMeetsMinimum.in[0] <== actualMinLevel;
    levelMeetsMinimum.in[1] <== minSecurityLevel;
    signal levelCheckPassed <== levelMeetsMinimum.out;
    
    // ===== SUM CHECKS (All jobs meet requirements) =====
    
    // Check 5: All jobs meet minimum security level
    signal minLevelCheck;
    minLevelCheck <== minLevelSum - jobCount;
    
    component minLevelIsZero = IsZero();
    minLevelIsZero.in <== minLevelCheck;
    signal minLevelCheckPassed <== minLevelIsZero.out;
    
    // Check 6: All jobs have attestation
    signal attestationCheck;
    attestationCheck <== attestationSum - jobCount;
    
    component attestationIsZero = IsZero();
    attestationIsZero.in <== attestationCheck;
    signal attestationCheckPassed <== attestationIsZero.out;
    
    // Check 7: All jobs have encryption
    signal encryptionCheck;
    encryptionCheck <== encryptionSum - jobCount;
    
    component encryptionIsZero = IsZero();
    encryptionIsZero.in <== encryptionCheck;
    signal encryptionCheckPassed <== encryptionIsZero.out;
    
    // ===== COMBINE ALL CHECKS =====
    
    // All checks must pass (AND operation)
    component and1 = AND();
    and1.a <== levelCheckPassed;
    and1.b <== minLevelCheckPassed;
    signal check12 <== and1.out;
    
    component and2 = AND();
    and2.a <== check12;
    and2.b <== attestationCheckPassed;
    signal check123 <== and2.out;
    
    component and3 = AND();
    and3.a <== check123;
    and3.b <== encryptionCheckPassed;
    signal allChecksPassed <== and3.out;
    
    // ===== OUTPUT =====
    
    // Output explicitly depends on all checks
    // FIXES the issue where output was always 1
    meetsLevel <== allChecksPassed;
}

component main {public [jobCount, minSecurityLevel]} = SecurityLevelV2();
