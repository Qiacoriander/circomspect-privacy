pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Age Proof Circuit
 * Proves that a user is above a certain age without revealing exact age
 * 
 * Public Inputs:
 * - minAge: Minimum age requirement
 * - isAboveAge: Boolean result (1 if above, 0 if not)
 * - commitmentHash: Hash of identity commitment
 * 
 * Private Inputs:
 * - age: User's actual age
 * - identitySecret: Secret used in commitment
 */

template AgeProof() {
    // Public inputs
    signal input minAge;
    signal input isAboveAge;
    signal input commitmentHash;
    
    // Private inputs
    signal input age;
    signal input identitySecret;
    
    // Intermediate signals
    signal ageCheck;
    
    // Component to check if age >= minAge
    component greaterEq = GreaterEqThan(32);
    greaterEq.in[0] <== age;
    greaterEq.in[1] <== minAge;
    
    // Verify the age check matches public output
    ageCheck <== greaterEq.out;
    ageCheck === isAboveAge;
    
    // Verify commitment (simplified for demo)
    // In production, this would hash age + identitySecret and check against commitmentHash
    signal commitmentCheck;
    commitmentCheck <== age * identitySecret;
    
    // Range check: age must be reasonable (0-150)
    component ageRangeCheck = LessThan(32);
    ageRangeCheck.in[0] <== age;
    ageRangeCheck.in[1] <== 150;
    ageRangeCheck.out === 1;
}

component main {public [minAge, isAboveAge, commitmentHash]} = AgeProof();
