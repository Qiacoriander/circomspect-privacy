pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Simplified circuit to prove marriage between two zkPassport holders
template SimpleMarriageProof() {
    // Private inputs (kept secret)
    signal input spouse1Nullifier;
    signal input spouse2Nullifier;
    signal input marriageSecret; // Secret known only to the married couple
    
    // Public inputs
    signal input marriageId;
    signal input timestamp;
    signal input requesterNullifier; // Who is requesting the proof
    
    // Outputs
    signal output isMarried;
    signal output proofHash;

    // Verify that the requester is one of the spouses
    component spouse1Check = IsEqual();
    spouse1Check.in[0] <== requesterNullifier;
    spouse1Check.in[1] <== spouse1Nullifier;
    
    component spouse2Check = IsEqual();
    spouse2Check.in[0] <== requesterNullifier;
    spouse2Check.in[1] <== spouse2Nullifier;
    
    // Requester must be either spouse1 or spouse2
    component isValidRequester = OR();
    isValidRequester.a <== spouse1Check.out;
    isValidRequester.b <== spouse2Check.out;
    isValidRequester.out === 1;

    // Generate marriage hash using Poseidon
    component marriageHash = Poseidon(4);
    marriageHash.inputs[0] <== spouse1Nullifier;
    marriageHash.inputs[1] <== spouse2Nullifier;
    marriageHash.inputs[2] <== marriageSecret;
    marriageHash.inputs[3] <== timestamp;
    
    // Verify marriage ID matches the hash
    component marriageIdCheck = IsEqual();
    marriageIdCheck.in[0] <== marriageId;
    marriageIdCheck.in[1] <== marriageHash.out;
    
    // If everything checks out, output that the marriage is valid
    isMarried <== marriageIdCheck.out;
    proofHash <== marriageHash.out;
}

// Template for OR gate (since circomlib might not have it)
template OR() {
    signal input a;
    signal input b;
    signal output out;
    
    out <== a + b - a*b;
}

component main {public [marriageId, timestamp, requesterNullifier]} = SimpleMarriageProof();