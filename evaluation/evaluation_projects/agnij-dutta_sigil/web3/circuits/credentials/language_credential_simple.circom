pragma circom 2.0.0;

include "../core/primitives/set_membership_lib.circom";
include "../core/primitives/range_proof_lib.circom";

/*
 * SimplifiedLanguageCredential Circuit
 * 
 * Proves programming language usage in a simplified way:
 * - Proves user actually used claimed languages (LOC thresholds)
 * - Maintains privacy of actual usage metrics
 */

template SimplifiedLanguageCredential(MAX_LANGUAGES) {
    // ========== PUBLIC INPUTS ==========
    signal input languageCount;                    // Number of languages (2, 5, 20, etc.)
    
    // ========== PRIVATE INPUTS ==========
    signal input languageHashes[MAX_LANGUAGES];    // Hashed language names (e.g., hash("Python"))
    signal input languageMask[MAX_LANGUAGES];      // 1 if language slot is used, 0 if empty
    signal input actualUsagePerLanguage[MAX_LANGUAGES]; // Actual LOC per language (private)
    signal input minimumUsageThreshold;            // Minimum LOC to count as "used"
    
    // ========== OUTPUTS ==========
    signal output isValid;                         // 1 if all claimed languages are proven
    signal output usageSum;                        // Sum of all language usage

    // ========== VALIDATION COMPONENTS ==========
    
    // 1. Count actual languages in use  
    component languageCounter = LanguageCounter(MAX_LANGUAGES);
    for (var i = 0; i < MAX_LANGUAGES; i++) {
        languageCounter.languageMask[i] <== languageMask[i];
    }
    languageCounter.expectedCount <== languageCount;
    
    // 2. Verify meaningful usage for each language
    component usageVerifiers[MAX_LANGUAGES];
    for (var i = 0; i < MAX_LANGUAGES; i++) {
        usageVerifiers[i] = LanguageUsageVerifier();
        usageVerifiers[i].isActive <== languageMask[i];
        usageVerifiers[i].actualUsage <== actualUsagePerLanguage[i];
        usageVerifiers[i].minimumThreshold <== minimumUsageThreshold;
    }
    
    // 3. Final validation
    component finalValidator = LanguageValidator(MAX_LANGUAGES);
    finalValidator.countValid <== languageCounter.countIsValid;
    for (var i = 0; i < MAX_LANGUAGES; i++) {
        finalValidator.usageValid[i] <== usageVerifiers[i].usageIsValid;
    }
    
    isValid <== finalValidator.allValid;
    
    // 4. Calculate usage sum
    component sumCalculator = UsageSum(MAX_LANGUAGES);
    for (var i = 0; i < MAX_LANGUAGES; i++) {
        sumCalculator.usageValues[i] <== actualUsagePerLanguage[i];
        sumCalculator.languageMask[i] <== languageMask[i];
    }
    
    usageSum <== sumCalculator.totalUsage;
}

/*
 * Counts active languages and verifies against expected count
 */
template LanguageCounter(N) {
    signal input languageMask[N];
    signal input expectedCount;
    signal output countIsValid;
    
    signal runningSum[N + 1];
    runningSum[0] <== 0;
    
    for (var i = 0; i < N; i++) {
        runningSum[i + 1] <== runningSum[i] + languageMask[i];
    }
    
    component isEqual = IsEqual();
    isEqual.in[0] <== runningSum[N];
    isEqual.in[1] <== expectedCount;
    
    countIsValid <== isEqual.out;
}

/*
 * Verifies that a language was meaningfully used (not just touched)
 */
template LanguageUsageVerifier() {
    signal input isActive;           // 1 if this language slot is active
    signal input actualUsage;        // Actual LOC written in this language
    signal input minimumThreshold;   // Minimum LOC to count as "used"
    
    signal output usageIsValid;
    
    // If language is active, verify meaningful usage
    component thresholdCheck = GreaterEqThan(32);
    thresholdCheck.in[0] <== actualUsage;
    thresholdCheck.in[1] <== minimumThreshold;
    
    // If inactive, automatically valid (1)
    // If active, must meet threshold
    component selector = Mux1();
    selector.c[0] <== 1;                    // If inactive (0), output 1 (valid)
    selector.c[1] <== thresholdCheck.out;   // If active (1), output threshold result
    selector.s <== isActive;
    
    usageIsValid <== selector.out;
}

/*
 * Validates all language proofs together
 */
template LanguageValidator(N) {
    signal input countValid;
    signal input usageValid[N];
    signal output allValid;
    
    // All usage proofs must be valid
    component andGates[N];
    signal allUsageValidSignal[N + 1];
    allUsageValidSignal[0] <== 1;
    
    for (var i = 0; i < N; i++) {
        andGates[i] = AND();
        andGates[i].a <== allUsageValidSignal[i];
        andGates[i].b <== usageValid[i];
        allUsageValidSignal[i + 1] <== andGates[i].out;
    }
    
    // Combine all validations
    component finalAnd = AND();
    finalAnd.a <== countValid;
    finalAnd.b <== allUsageValidSignal[N];
    
    allValid <== finalAnd.out;
}

/*
 * Calculates the sum of usage across all active languages
 */
template UsageSum(N) {
    signal input usageValues[N];
    signal input languageMask[N];
    signal output totalUsage;
    
    signal runningSum[N + 1];
    runningSum[0] <== 0;
    
    for (var i = 0; i < N; i++) {
        runningSum[i + 1] <== runningSum[i] + (usageValues[i] * languageMask[i]);
    }
    
    totalUsage <== runningSum[N];
}

component main = SimplifiedLanguageCredential(10); 