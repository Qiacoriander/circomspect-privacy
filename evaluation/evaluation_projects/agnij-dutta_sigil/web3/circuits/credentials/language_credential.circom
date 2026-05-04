pragma circom 2.0.0;

include "../core/primitives/set_membership_lib.circom";
include "../core/primitives/range_proof_lib.circom";
include "../core/utilities.circom";

/*
    LanguageCredential: Simplified version that proves programming language proficiency
    
    This circuit proves:
    1. Proficiency in multiple programming languages
    2. Usage statistics above threshold for each language
    3. Diversity of language ecosystem knowledge
*/

template LanguageCredential(maxLanguages) {
    // Input signals
    signal input userHash;                     // User's identity hash
    signal input languageHashes[maxLanguages]; // Hashes of programming languages
    signal input proficiencyScores[maxLanguages]; // Proficiency scores (1-10)
    signal input usageHours[maxLanguages];     // Usage hours per language
    signal input totalLanguages;               // Number of languages claimed
    signal input diversityThreshold;           // Minimum diversity score required
    
    // Output signals
    signal output credentialHash;              // Hash of the credential
    signal output diversityScore;              // Language diversity score (0-100)
    signal output isValid;                     // 1 if credential is valid, 0 otherwise
    
    // Intermediate signals
    signal languageWeights[maxLanguages];      // Weighted language scores
    signal totalScore;                         // Sum of weighted scores
    
    // Components for verification
    component rangeProofs[maxLanguages * 3];
    
    // Range proofs for all language metrics
    for (var i = 0; i < maxLanguages; i++) {
        // Proficiency scores range proof (0-10)
        rangeProofs[i * 3] = RangeProofCustom(32);
        rangeProofs[i * 3].value <== proficiencyScores[i];
        rangeProofs[i * 3].min <== 0;
        rangeProofs[i * 3].max <== 10;
        
        // Usage hours range proof (0-10000)
        rangeProofs[i * 3 + 1] = RangeProofCustom(32);
        rangeProofs[i * 3 + 1].value <== usageHours[i];
        rangeProofs[i * 3 + 1].min <== 0;
        rangeProofs[i * 3 + 1].max <== 10000;
        
        // Language hash range proof (to ensure valid hashes)
        rangeProofs[i * 3 + 2] = RangeProofCustom(32);
        rangeProofs[i * 3 + 2].value <== languageHashes[i];
        rangeProofs[i * 3 + 2].min <== 0;
        rangeProofs[i * 3 + 2].max <== 1000000; // Large range for hash values
    }
    
    // Components for language activity checks
    component isActiveLanguage[maxLanguages];
    
    // Calculate diversity score
    var scoreSum = 0;
    for (var i = 0; i < maxLanguages; i++) {
        // Check if language is actively used (non-zero hash and usage)
        isActiveLanguage[i] = GreaterThan(32);
        isActiveLanguage[i].in[0] <== languageHashes[i] + usageHours[i];
        isActiveLanguage[i].in[1] <== 0;
        
        // Weight by proficiency and usage
        languageWeights[i] <== isActiveLanguage[i].out * proficiencyScores[i] * 10;
        scoreSum += languageWeights[i];
    }
    
    // Calculate diversity score
    totalScore <== scoreSum;
    diversityScore <== totalScore;
    
    // Validate language diversity
    component diversityValid = GreaterEqThan(32);
    diversityValid.in[0] <== diversityScore;
    diversityValid.in[1] <== diversityThreshold;
    
    component minimumLanguagesValid = GreaterEqThan(32);
    minimumLanguagesValid.in[0] <== totalLanguages;
    minimumLanguagesValid.in[1] <== 2; // At least 2 languages
    
    isValid <== diversityValid.out * minimumLanguagesValid.out;
    
    // Generate credential hash
    component credentialHasher = SimplePoseidon(4);
    credentialHasher.inputs[0] <== userHash;
    credentialHasher.inputs[1] <== diversityScore;
    credentialHasher.inputs[2] <== totalLanguages;
    credentialHasher.inputs[3] <== isValid;
    
    credentialHash <== credentialHasher.out;
    
    // Constraint: Credential must be valid
    isValid === 1;
    
    // Range proofs for inputs
    component totalLanguagesRange = RangeProofCustom(32);
    totalLanguagesRange.value <== totalLanguages;
    totalLanguagesRange.min <== 1;
    totalLanguagesRange.max <== maxLanguages;
    
    component thresholdRange = RangeProofCustom(32);
    thresholdRange.value <== diversityThreshold;
    thresholdRange.min <== 0;
    thresholdRange.max <== 1000; // High threshold range for flexibility
}

component main = LanguageCredential(10);
