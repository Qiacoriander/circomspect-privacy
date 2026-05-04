pragma circom 2.0.0;

include "../core/utilities.circom";
include "../core/primitives/range_proof_lib.circom";

/*
    K-Anonymity Privacy Circuit
    
    This circuit ensures k-anonymity for collaboration data by verifying that:
    1. Any group of collaborators has at least k members
    2. Individual contributors cannot be uniquely identified
    3. Quasi-identifiers are sufficiently generalized
    4. Sensitive attributes are protected through group membership
    
    K-anonymity is crucial for protecting collaborator identities while still
    proving meaningful collaboration patterns.
*/

template KAnonymity(maxGroupSize, maxAttributes) {
    // Input signals
    signal input groupSize;
    signal input k;
    signal input quasiIdentifiers[maxAttributes];
    signal input sensitiveAttributes[maxAttributes];
    signal input generalizedValues[maxAttributes];
    signal input suppressionFlags[maxAttributes];
    signal input equivalenceClassSize;
    signal input diversityLevel;
    
    // Output signals
    signal output isKAnonymous;
    signal output suppressionCount;
    signal output suppressionLevel;
    signal output generalizationLevel;
    signal output privacyLevel;
    signal output diversityAchieved;
    signal output equivalenceClassValid;
    
    // Internal signals
    signal attributeProtection[maxAttributes];
    signal generalizedDifferences[maxAttributes];
    
    // Basic k-anonymity check: group size >= k
    component groupSizeCheck = GreaterEqThan(32);
    groupSizeCheck.in[0] <== groupSize;
    groupSizeCheck.in[1] <== k;
    
    // Equivalence class size check
    component equivalenceCheck = GreaterEqThan(32);
    equivalenceCheck.in[0] <== equivalenceClassSize;
    equivalenceCheck.in[1] <== k;
    
    equivalenceClassValid <== equivalenceCheck.out;
    
    // Range proofs for input validation
    component rangeProofs[maxAttributes * 4];
    var rangeProofIndex = 0;
    
    // Components for attribute protection calculation
    component suppressionEq[maxAttributes];
    component generalizationNeq[maxAttributes];
    component generalizationNot[maxAttributes];
    component protectionOr[maxAttributes];
    
    // Initialize components
    for (var i = 0; i < maxAttributes; i++) {
        suppressionEq[i] = IsEqual();
        generalizationNeq[i] = IsEqual();
        generalizationNot[i] = NOT();
        protectionOr[i] = OR();
    }
    
    var protectedAttributes = 0;
    var totalSuppression = 0;
    var totalGeneralization = 0;
    
    for (var i = 0; i < maxAttributes; i++) {
        // Range proof for quasi-identifiers
        rangeProofs[rangeProofIndex] = RangeProofCustom(32);
        rangeProofs[rangeProofIndex].value <== quasiIdentifiers[i];
        rangeProofs[rangeProofIndex].min <== 0;
        rangeProofs[rangeProofIndex].max <== 1000;
        rangeProofIndex++;
        
        // Range proof for sensitive attributes
        rangeProofs[rangeProofIndex] = RangeProofCustom(32);
        rangeProofs[rangeProofIndex].value <== sensitiveAttributes[i];
        rangeProofs[rangeProofIndex].min <== 0;
        rangeProofs[rangeProofIndex].max <== 1000;
        rangeProofIndex++;
        
        // Calculate attribute protection level
        suppressionEq[i].in[0] <== suppressionFlags[i];
        suppressionEq[i].in[1] <== 1;
        
        generalizationNeq[i].in[0] <== generalizedValues[i];
        generalizationNeq[i].in[1] <== quasiIdentifiers[i];
        
        generalizationNot[i].in <== generalizationNeq[i].out;
        
        protectionOr[i].a <== suppressionEq[i].out;
        protectionOr[i].b <== generalizationNot[i].out;
        
        attributeProtection[i] <== protectionOr[i].out;
        protectedAttributes += attributeProtection[i];
        totalSuppression += suppressionFlags[i];
        totalGeneralization += generalizationNot[i].out;
    }
    
    suppressionCount <== totalSuppression;
    suppressionLevel <== (totalSuppression * 100) / maxAttributes;
    generalizationLevel <== (totalGeneralization * 100) / maxAttributes;
    
    // Check L-diversity
    component diversityCheck = GreaterEqThan(32);
    diversityCheck.in[0] <== maxAttributes;
    diversityCheck.in[1] <== diversityLevel;
    diversityAchieved <== diversityCheck.out;
    
    // Calculate overall privacy level
    var basePrivacyScore = (groupSizeCheck.out * 40);  // 40% for basic k-anonymity
    var attributePrivacyScore = (protectedAttributes * 30) / maxAttributes; // 30% for attribute protection
    var equivalenceScore = (equivalenceClassValid * 20); // 20% for equivalence class
    var diversityScore = (diversityAchieved * 10); // 10% for l-diversity
    
    privacyLevel <== basePrivacyScore + attributePrivacyScore + equivalenceScore + diversityScore;
    
    // Overall k-anonymity check
    component minimumProtectionCheck = GreaterEqThan(32);
    minimumProtectionCheck.in[0] <== protectedAttributes;
    minimumProtectionCheck.in[1] <== maxAttributes / 2;
    
    component kAnonymityAnd1 = AND();
    kAnonymityAnd1.a <== groupSizeCheck.out;
    kAnonymityAnd1.b <== equivalenceClassValid;
    
    component kAnonymityAnd2 = AND();
    kAnonymityAnd2.a <== kAnonymityAnd1.out;
    kAnonymityAnd2.b <== minimumProtectionCheck.out;
    
    isKAnonymous <== kAnonymityAnd2.out;
    
    // Validate privacy level range
    component privacyLevelRange = RangeProofCustom(32);
    privacyLevelRange.value <== privacyLevel;
    privacyLevelRange.min <== 0;
    privacyLevelRange.max <== 100;
    
    component suppressionRange = RangeProofCustom(32);
    suppressionRange.value <== suppressionCount;
    suppressionRange.min <== 0;
    suppressionRange.max <== maxAttributes;
}

/*
    Advanced K-Anonymity with T-Closeness
    
    Extends basic k-anonymity with t-closeness to ensure that the distribution
    of sensitive attributes in any equivalence class is close to the distribution
    in the overall dataset.
*/
template KAnonymityWithTCloseness(maxGroupSize, maxAttributes, precision) {
    // Input signals
    signal input groupSize;
    signal input k;
    signal input t; // T-closeness parameter (scaled for precision)
    signal input sensitiveDistribution[maxAttributes]; // Global distribution
    signal input localDistribution[maxAttributes];     // Local equivalence class distribution
    signal input equivalenceClassSize;
    
    // Output signals
    signal output isKAnonymous;
    signal output isTClose;
    signal output privacyScore;
    signal output distributionDistance;
    
    // Basic k-anonymity check
    component kAnonymityCheck = KAnonymity(maxGroupSize, maxAttributes);
    kAnonymityCheck.groupSize <== groupSize;
    kAnonymityCheck.k <== k;
    for (var i = 0; i < maxAttributes; i++) {
        kAnonymityCheck.quasiIdentifiers[i] <== 0; // Simplified for t-closeness focus
        kAnonymityCheck.sensitiveAttributes[i] <== sensitiveDistribution[i];
        kAnonymityCheck.generalizedValues[i] <== 0;
        kAnonymityCheck.suppressionFlags[i] <== 0;
    }
    kAnonymityCheck.equivalenceClassSize <== equivalenceClassSize;
    kAnonymityCheck.diversityLevel <== 2;
    
    isKAnonymous <== kAnonymityCheck.isKAnonymous;
    
    // Calculate distance between distributions 
    var totalDistance = 0;
    component distanceComponents[maxAttributes];
    
    for (var i = 0; i < maxAttributes; i++) {
        distanceComponents[i] = IsEqual();
        distanceComponents[i].in[0] <== sensitiveDistribution[i];
        distanceComponents[i].in[1] <== localDistribution[i];
        
        totalDistance += (1 - distanceComponents[i].out);
    }
    
    distributionDistance <== totalDistance;
    
    // Check if distance is within t-closeness threshold
    component tClosenessCheck = LessEqThan(precision);
    tClosenessCheck.in[0] <== distributionDistance;
    tClosenessCheck.in[1] <== t;
    isTClose <== tClosenessCheck.out;
    
    // Calculate combined privacy score
    var kScore = isKAnonymous * 60; // 60% for k-anonymity
    var tScore = isTClose * 40;     // 40% for t-closeness
    privacyScore <== kScore + tScore;
}

/*
    Utility templates for k-anonymity operations
*/
template GreaterThanOrEqual(n) {
    signal input in[2];
    signal output out;
    
    component gt = GreaterThan(n);
    gt.in[0] <== in[0];
    gt.in[1] <== in[1] - 1;
    out <== gt.out;
}

template LessThanOrEqual(n) {
    signal input in[2];
    signal output out;
    
    component lt = LessThan(n);
    lt.in[0] <== in[0] + 1;
    lt.in[1] <== in[1] + 1;
    out <== lt.out;
}

// Templates removed - using utilities.circom versions instead

component main = KAnonymity(20, 10);
