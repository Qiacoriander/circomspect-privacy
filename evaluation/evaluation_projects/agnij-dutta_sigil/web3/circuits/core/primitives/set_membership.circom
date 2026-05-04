pragma circom 2.0.0;

include "../utilities.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * Set Membership Circuit
 * Proves that a private value is a member of a public set
 * without revealing which element it is
 */
template SetMembership(setSize) {
    signal input value;              // Private value to prove membership
    signal input set[setSize];       // Public set of allowed values
    signal output isMember;          // 1 if value is in set, 0 otherwise
    
    component equals[setSize];
    signal results[setSize];
    
    // Check equality with each set element
    for (var i = 0; i < setSize; i++) {
        equals[i] = IsEqual();
        equals[i].in[0] <== value;
        equals[i].in[1] <== set[i];
        results[i] <== equals[i].out;
    }
    
    // OR all the equality results
    signal orResults[setSize];
    orResults[0] <== results[0];
    
    component orGates[setSize - 1];
    for (var i = 1; i < setSize; i++) {
        orGates[i - 1] = OR();
        orGates[i - 1].a <== orResults[i - 1];
        orGates[i - 1].b <== results[i];
        orResults[i] <== orGates[i - 1].out;
    }
    
    isMember <== orResults[setSize - 1];
}

/*
 * Multi Set Membership
 * Proves multiple values are each members of corresponding sets
 */
template MultiSetMembership(n, setSize) {
    signal input values[n];
    signal input sets[n][setSize];
    signal output allMembers;
    
    component membershipChecks[n];
    component andGates[n > 1 ? n - 1 : 1];
    
    // Check membership for each value
    for (var i = 0; i < n; i++) {
        membershipChecks[i] = SetMembership(setSize);
        membershipChecks[i].value <== values[i];
        for (var j = 0; j < setSize; j++) {
            membershipChecks[i].set[j] <== sets[i][j];
        }
    }
    
    // AND all results
    if (n == 1) {
        allMembers <== membershipChecks[0].isMember;
    } else {
        andGates[0] = AND();
        andGates[0].a <== membershipChecks[0].isMember;
        andGates[0].b <== membershipChecks[1].isMember;
        
        for (var i = 1; i < n - 1; i++) {
            andGates[i] = AND();
            andGates[i].a <== andGates[i - 1].out;
            andGates[i].b <== membershipChecks[i + 1].isMember;
        }
        
        allMembers <== andGates[n - 2].out;
    }
}

/*
 * Set Intersection Proof
 * Proves that the intersection of two sets is non-empty
 */
template SetIntersection(set1Size, set2Size) {
    signal input set1[set1Size];
    signal input set2[set2Size];
    signal output hasIntersection;
    
    component equals[set1Size][set2Size];
    signal intersectionResults[set1Size][set2Size];
    
    // Check all pairs for equality
    for (var i = 0; i < set1Size; i++) {
        for (var j = 0; j < set2Size; j++) {
            equals[i][j] = IsEqual();
            equals[i][j].in[0] <== set1[i];
            equals[i][j].in[1] <== set2[j];
            intersectionResults[i][j] <== equals[i][j].out;
        }
    }
    
    // OR all results
    signal orResults[set1Size * set2Size];
    var index = 0;
    for (var i = 0; i < set1Size; i++) {
        for (var j = 0; j < set2Size; j++) {
            orResults[index] <== intersectionResults[i][j];
            index++;
        }
    }
    
    // Combine all OR results
    signal finalOr[set1Size * set2Size];
    finalOr[0] <== orResults[0];
    
    component orGates[set1Size * set2Size - 1];
    for (var i = 1; i < set1Size * set2Size; i++) {
        orGates[i - 1] = OR();
        orGates[i - 1].a <== finalOr[i - 1];
        orGates[i - 1].b <== orResults[i];
        finalOr[i] <== orGates[i - 1].out;
    }
    
    hasIntersection <== finalOr[set1Size * set2Size - 1];
}

/*
 * Subset Proof
 * Proves that set1 is a subset of set2
 */
template SubsetProof(set1Size, set2Size) {
    signal input set1[set1Size];
    signal input set2[set2Size];
    signal output isSubset;
    
    component membershipChecks[set1Size];
    component andGates[set1Size > 1 ? set1Size - 1 : 1];
    
    // Check that each element of set1 is in set2
    for (var i = 0; i < set1Size; i++) {
        membershipChecks[i] = SetMembership(set2Size);
        membershipChecks[i].value <== set1[i];
        for (var j = 0; j < set2Size; j++) {
            membershipChecks[i].set[j] <== set2[j];
        }
    }
    
    // AND all membership results
    if (set1Size == 1) {
        isSubset <== membershipChecks[0].isMember;
    } else {
        andGates[0] = AND();
        andGates[0].a <== membershipChecks[0].isMember;
        andGates[0].b <== membershipChecks[1].isMember;
        
        for (var i = 1; i < set1Size - 1; i++) {
            andGates[i] = AND();
            andGates[i].a <== andGates[i - 1].out;
            andGates[i].b <== membershipChecks[i + 1].isMember;
        }
        
        isSubset <== andGates[set1Size - 2].out;
    }
}

/*
 * PrivateSetMembership proves membership without revealing the set
 * Uses commitment to the set and merkle proof
 */
template PrivateSetMembership(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;
    signal output isMember;
    
    component merkleProof = MerkleTreeChecker(depth);
    merkleProof.leaf <== leaf;
    merkleProof.root <== root;
    
    for (var i = 0; i < depth; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    
    isMember <== 1; // If constraints pass, membership is proven
}

// Utility templates removed - they are included from ../utilities.circom

template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    component selectors[levels];
    component hashers[levels];
    
    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].c[0] <== i == 0 ? leaf : hashers[i-1].out;
        selectors[i].c[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
    }
    
    root === hashers[levels-1].out;
}

template DualMux() {
    signal input c[2];
    signal input s;
    signal output out[2];
    
    s * (1 - s) === 0;
    out[0] <== (c[1] - c[0]) * s + c[0];
    out[1] <== (c[0] - c[1]) * s + c[1];
}

component main = SetMembership(10);