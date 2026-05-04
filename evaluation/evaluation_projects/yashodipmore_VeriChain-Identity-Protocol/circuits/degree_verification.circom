pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/**
 * VeriChain Degree Verification Circuit
 * 
 * This circuit allows a user to prove they hold a university degree
 * without revealing which university or what degree.
 * 
 * Public Inputs:
 * - degreeTypeHash: Hash of accepted degree types (e.g., Bachelor's = 1, Master's = 2)
 * - commitment: Hash of (universityId, degreeType, graduationYear, secret)
 * 
 * Private Inputs:
 * - universityId: Identifier of the university
 * - degreeType: Type of degree (1=Bachelor, 2=Master, 3=PhD)
 * - graduationYear: Year of graduation
 * - secret: User's secret for commitment
 */
template DegreeVerification() {
    // Public inputs
    signal input minDegreeType; // 1=Bachelor, 2=Master, 3=PhD
    signal input commitment;
    
    // Private inputs
    signal input universityId;
    signal input degreeType;
    signal input graduationYear;
    signal input secret;
    
    // Outputs
    signal output hasValidDegree;
    signal output degreeCommitment;
    
    // Verify commitment
    component poseidon = Poseidon(4);
    poseidon.inputs[0] <== universityId;
    poseidon.inputs[1] <== degreeType;
    poseidon.inputs[2] <== graduationYear;
    poseidon.inputs[3] <== secret;
    commitment === poseidon.out;
    
    // Check degreeType >= minDegreeType
    component gte = GreaterEqThan(4); // 4 bits for degree types
    gte.in[0] <== degreeType;
    gte.in[1] <== minDegreeType;
    
    hasValidDegree <== gte.out;
    
    // Create a commitment for the degree (without revealing university)
    component degreeHash = Poseidon(2);
    degreeHash.inputs[0] <== degreeType;
    degreeHash.inputs[1] <== secret;
    degreeCommitment <== degreeHash.out;
    
    // Ensure valid degree
    hasValidDegree === 1;
}

component main {public [minDegreeType, commitment]} = DegreeVerification();
