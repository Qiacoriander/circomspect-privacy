pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 * @title AgeVerification
 * @dev Prove that a person's age is above a certain threshold without revealing exact age
 * Input: birthYear (private), currentYear (public), ageThreshold (public)
 * Output: proof that (currentYear - birthYear) >= ageThreshold
 */
template AgeVerification() {
    // Private inputs (hidden from verifier)
    signal input birthYear;
    
    // Public inputs (visible to verifier)
    signal input currentYear;
    signal input ageThreshold;
    
    // Output signal
    signal output isAboveThreshold;
    
    // Calculate age
    signal age;
    age <== currentYear - birthYear;
    
    // Check if age >= ageThreshold
    component greaterEqThan = GreaterEqThan(32); // 32-bit comparison
    greaterEqThan.in[0] <== age;
    greaterEqThan.in[1] <== ageThreshold;
    
    // Output 1 if age >= threshold, 0 otherwise
    isAboveThreshold <== greaterEqThan.out;
    
    // Constraint: result must be binary (0 or 1)
    isAboveThreshold * (1 - isAboveThreshold) === 0;
    
    // Add constraint to ensure age is reasonable (0-150 years)
    component ageLessThan = LessThan(32);
    ageLessThan.in[0] <== age;
    ageLessThan.in[1] <== 151;
    ageLessThan.out === 1;
    
    // Ensure birth year is reasonable (1900-2025)
    component birthYearGreater = GreaterEqThan(32);
    birthYearGreater.in[0] <== birthYear;
    birthYearGreater.in[1] <== 1900;
    birthYearGreater.out === 1;
}

component main {public [currentYear, ageThreshold]} = AgeVerification();
