pragma circom 2.0.0;

// Include core primitives
include "../primitives/merkle_tree.circom";
include "../primitives/range_proof.circom";
include "../primitives/hash_chain.circom";
include "../primitives/signature_verify.circom";

/*
 * ProofCombiner - Combine multiple ZK proofs into a single aggregated proof
 * 
 * This circuit enables:
 * 1. Aggregation of multiple independent ZK proofs
 * 2. Batch verification of combined proofs
 * 3. Proof compression and optimization
 * 4. Cross-circuit proof validation
 * 5. Hierarchical proof structures
 */
template ProofCombiner(MAX_PROOFS, PROOF_SIZE) {
    // Input signals for proof combination
    signal input proofs[MAX_PROOFS][PROOF_SIZE];                // Individual proofs to combine
    signal input publicInputs[MAX_PROOFS][PROOF_SIZE];          // Public inputs for each proof
    signal input proofTypes[MAX_PROOFS];                        // Type of each proof (Groth16, PLONK, etc.)
    signal input validationFlags[MAX_PROOFS];                   // Which proofs to include in combination
    signal input combinationMode;                               // Combination mode: 1=aggregate, 2=batch, 3=recursive
    signal input verificationKeys[MAX_PROOFS][PROOF_SIZE];      // Verification keys for each proof
    signal input proofMetadata[MAX_PROOFS][4];                  // Metadata: [timestamp, circuit_id, version, flags]
    
    // Output signals
    signal output combinedProof[PROOF_SIZE];                    // Final combined proof
    signal output combinedPublicInputs[PROOF_SIZE];             // Combined public inputs
    signal output verificationResult;                           // Overall verification result
    signal output proofIntegrity;                               // Integrity hash of all proofs
    signal output batchSize;                                    // Number of proofs successfully combined
    signal output compressionRatio;                             // Compression achieved through combination
    
    // Internal signals for proof processing
    signal normalizedProofs[MAX_PROOFS][PROOF_SIZE];            // Normalized proof format
    signal verificationResults[MAX_PROOFS];                     // Individual verification results
    signal proofHashes[MAX_PROOFS];                             // Hash of each proof
    signal weightedProofs[MAX_PROOFS][PROOF_SIZE];              // Weighted proofs for aggregation
    signal aggregationWeights[MAX_PROOFS];                      // Weights for proof aggregation
    signal validProofs[MAX_PROOFS];                             // Valid proof flags
    
    // Components for proof processing
    component proofVerifiers[MAX_PROOFS];
    component proofNormalizers[MAX_PROOFS];
    component proofHashers[MAX_PROOFS];
    component aggregator = ProofAggregator(MAX_PROOFS, PROOF_SIZE);
    component batchVerifier = BatchVerifier(MAX_PROOFS, PROOF_SIZE);
    component recursiveVerifier = RecursiveVerifier(MAX_PROOFS, PROOF_SIZE);
    component integrityChecker = ProofIntegrityChecker(MAX_PROOFS);
    component compressionAnalyzer = CompressionAnalyzer(MAX_PROOFS, PROOF_SIZE);
    
    // Hash chain for proof integrity
    component proofHashChain = HashChain(MAX_PROOFS);
    
    // Range proofs for input validation
    component proofRanges[MAX_PROOFS][PROOF_SIZE];
    component typeRanges[MAX_PROOFS];
    component modeRange = RangeProof(8);
    
    // Validate combination mode
    modeRange.value <== combinationMode;
    modeRange.minRange <== 1;
    modeRange.maxRange <== 3;
    modeRange.isValid === 1;
    
    // Validate and normalize input proofs
    for (var i = 0; i < MAX_PROOFS; i++) {
        // Validate proof type
        typeRanges[i] = RangeProof(8);
        typeRanges[i].value <== proofTypes[i];
        typeRanges[i].minRange <== 0;
        typeRanges[i].maxRange <== 5; // Support 5 proof types
        typeRanges[i].isValid === 1;
        
        // Validate proof elements
        for (var j = 0; j < PROOF_SIZE; j++) {
            proofRanges[i][j] = RangeProof(32);
            proofRanges[i][j].value <== proofs[i][j];
            proofRanges[i][j].minRange <== 0;
            proofRanges[i][j].maxRange <== 2**31 - 1;
            proofRanges[i][j].isValid === 1;
        }
        
        // Normalize proof format
        proofNormalizers[i] = ProofNormalizer(PROOF_SIZE);
        proofNormalizers[i].proofType <== proofTypes[i];
        proofNormalizers[i].validationFlag <== validationFlags[i];
        
        for (var j = 0; j < PROOF_SIZE; j++) {
            proofNormalizers[i].rawProof[j] <== proofs[i][j];
            proofNormalizers[i].publicInputs[j] <== publicInputs[i][j];
            proofNormalizers[i].verificationKey[j] <== verificationKeys[i][j];
        }
        
        // Store normalized proofs
        for (var j = 0; j < PROOF_SIZE; j++) {
            normalizedProofs[i][j] <== proofNormalizers[i].normalizedProof[j];
        }
        
        validProofs[i] <== proofNormalizers[i].isValid;
    }
    
    // Verify individual proofs
    for (var i = 0; i < MAX_PROOFS; i++) {
        proofVerifiers[i] = ProofVerifier(PROOF_SIZE);
        proofVerifiers[i].proofType <== proofTypes[i];
        proofVerifiers[i].validFlag <== validProofs[i];
        
        for (var j = 0; j < PROOF_SIZE; j++) {
            proofVerifiers[i].proof[j] <== normalizedProofs[i][j];
            proofVerifiers[i].publicInputs[j] <== publicInputs[i][j];
            proofVerifiers[i].verificationKey[j] <== verificationKeys[i][j];
        }
        
        verificationResults[i] <== proofVerifiers[i].isValid;
    }
    
    // Hash individual proofs for integrity
    for (var i = 0; i < MAX_PROOFS; i++) {
        proofHashers[i] = ProofHasher(PROOF_SIZE);
        
        for (var j = 0; j < PROOF_SIZE; j++) {
            proofHashers[i].proof[j] <== normalizedProofs[i][j];
            proofHashers[i].publicInputs[j] <== publicInputs[i][j];
        }
        
        proofHashers[i].timestamp <== proofMetadata[i][0];
        proofHashers[i].circuitId <== proofMetadata[i][1];
        proofHashes[i] <== proofHashers[i].hash;
    }
    
    // Calculate aggregation weights based on proof types and metadata
    for (var i = 0; i < MAX_PROOFS; i++) {
        component weightCalc = AggregationWeightCalculator();
        weightCalc.proofType <== proofTypes[i];
        weightCalc.timestamp <== proofMetadata[i][0];
        weightCalc.circuitId <== proofMetadata[i][1];
        weightCalc.version <== proofMetadata[i][2];
        weightCalc.validFlag <== validProofs[i] * verificationResults[i];
        aggregationWeights[i] <== weightCalc.weight;
    }
    
    // Apply weights to proofs for aggregation
    for (var i = 0; i < MAX_PROOFS; i++) {
        for (var j = 0; j < PROOF_SIZE; j++) {
            component weightMult = Multiplier();
            weightMult.in[0] <== normalizedProofs[i][j];
            weightMult.in[1] <== aggregationWeights[i];
            weightedProofs[i][j] <== weightMult.out;
        }
    }
    
    // Combine proofs based on combination mode
    component modeSelector = CombinationModeSelector(MAX_PROOFS, PROOF_SIZE);
    modeSelector.mode <== combinationMode;
    
    for (var i = 0; i < MAX_PROOFS; i++) {
        modeSelector.validFlags[i] <== validProofs[i] * verificationResults[i];
        for (var j = 0; j < PROOF_SIZE; j++) {
            modeSelector.weightedProofs[i][j] <== weightedProofs[i][j];
            modeSelector.publicInputs[i][j] <== publicInputs[i][j];
        }
    }
    
    // Generate combined proof and public inputs
    for (var i = 0; i < PROOF_SIZE; i++) {
        combinedProof[i] <== modeSelector.combinedProof[i];
        combinedPublicInputs[i] <== modeSelector.combinedPublicInputs[i];
    }
    
    // Build proof integrity hash chain
    for (var i = 0; i < MAX_PROOFS; i++) {
        proofHashChain.values[i] <== proofHashes[i] * validProofs[i];
    }
    proofIntegrity <== proofHashChain.root;
    
    // Count valid proofs in batch
    component batchCounter = Sum(MAX_PROOFS);
    for (var i = 0; i < MAX_PROOFS; i++) {
        batchCounter.values[i] <== validProofs[i] * verificationResults[i];
    }
    batchSize <== batchCounter.out;
    
    // Analyze compression achieved
    for (var i = 0; i < MAX_PROOFS; i++) {
        compressionAnalyzer.originalSizes[i] <== PROOF_SIZE * validProofs[i];
        compressionAnalyzer.validFlags[i] <== validProofs[i];
    }
    compressionAnalyzer.combinedSize <== PROOF_SIZE;
    compressionRatio <== compressionAnalyzer.ratio;
    
    // Perform integrity checking
    for (var i = 0; i < MAX_PROOFS; i++) {
        integrityChecker.proofHashes[i] <== proofHashes[i];
        integrityChecker.verificationResults[i] <== verificationResults[i];
        integrityChecker.validFlags[i] <== validProofs[i];
    }
    
    // Final verification result
    component finalVerification = FinalVerificationCheck(MAX_PROOFS);
    for (var i = 0; i < MAX_PROOFS; i++) {
        finalVerification.individualResults[i] <== verificationResults[i];
        finalVerification.validFlags[i] <== validProofs[i];
    }
    finalVerification.integrityValid <== integrityChecker.integrityValid;
    finalVerification.batchSize <== batchSize;
    verificationResult <== finalVerification.overallResult;
    
    // Validation constraints
    component validCombination = GreaterThan(16);
    validCombination.in[0] <== verificationResult;
    validCombination.in[1] <== 0;
    validCombination.out === 1;
    
    // At least one proof must be valid
    component hasValidProof = GreaterThan(16);
    hasValidProof.in[0] <== batchSize;
    hasValidProof.in[1] <== 0;
    hasValidProof.out === 1;
    
    // Integrity must be maintained
    component integrityValid = GreaterThan(32);
    integrityValid.in[0] <== proofIntegrity;
    integrityValid.in[1] <== 0;
    integrityValid.out === 1;
}

/*
 * Helper template: Proof normalizer for different proof types
 */
template ProofNormalizer(PROOF_SIZE) {
    signal input proofType;
    signal input validationFlag;
    signal input rawProof[PROOF_SIZE];
    signal input publicInputs[PROOF_SIZE];
    signal input verificationKey[PROOF_SIZE];
    signal output normalizedProof[PROOF_SIZE];
    signal output isValid;
    
    // Proof type normalization:
    // 1 = Groth16
    // 2 = PLONK
    // 3 = STARK
    // 4 = Bulletproofs
    // 5 = Custom
    
    component typeValidator = RangeProof(8);
    typeValidator.value <== proofType;
    typeValidator.minRange <== 1;
    typeValidator.maxRange <== 5;
    
    // Normalize proof based on type (simplified)
    component normalizer = GenericProofNormalizer(PROOF_SIZE);
    normalizer.proofType <== proofType;
    normalizer.validationFlag <== validationFlag;
    
    for (var i = 0; i < PROOF_SIZE; i++) {
        normalizer.rawProof[i] <== rawProof[i];
        normalizer.publicInputs[i] <== publicInputs[i];
        normalizedProof[i] <== normalizer.normalizedProof[i];
    }
    
    isValid <== typeValidator.isValid * validationFlag * normalizer.isValid;
}

/*
 * Helper template: Proof verifier for different proof systems
 */
template ProofVerifier(PROOF_SIZE) {
    signal input proofType;
    signal input validFlag;
    signal input proof[PROOF_SIZE];
    signal input publicInputs[PROOF_SIZE];
    signal input verificationKey[PROOF_SIZE];
    signal output isValid;
    
    // Generic proof verification (simplified for circuit efficiency)
    component verifier = GenericVerifier(PROOF_SIZE);
    verifier.proofType <== proofType;
    verifier.validFlag <== validFlag;
    
    for (var i = 0; i < PROOF_SIZE; i++) {
        verifier.proof[i] <== proof[i];
        verifier.publicInputs[i] <== publicInputs[i];
        verifier.verificationKey[i] <== verificationKey[i];
    }
    
    isValid <== verifier.verificationResult;
}

/*
 * Helper template: Proof hasher for integrity checking
 */
template ProofHasher(PROOF_SIZE) {
    signal input proof[PROOF_SIZE];
    signal input publicInputs[PROOF_SIZE];
    signal input timestamp;
    signal input circuitId;
    signal output hash;
    
    // Hash proof with metadata
    component hasher = HashChain(PROOF_SIZE * 2 + 2);
    
    // Include proof elements
    for (var i = 0; i < PROOF_SIZE; i++) {
        hasher.values[i] <== proof[i];
        hasher.values[PROOF_SIZE + i] <== publicInputs[i];
    }
    
    // Include metadata
    hasher.values[PROOF_SIZE * 2] <== timestamp;
    hasher.values[PROOF_SIZE * 2 + 1] <== circuitId;
    
    hash <== hasher.root;
}

/*
 * Helper template: Aggregation weight calculator
 */
template AggregationWeightCalculator() {
    signal input proofType;
    signal input timestamp;
    signal input circuitId;
    signal input version;
    signal input validFlag;
    signal output weight;
    
    // Calculate weight based on proof characteristics
    component weightCalc = WeightCalculator();
    weightCalc.proofType <== proofType;
    weightCalc.timestamp <== timestamp;
    weightCalc.circuitId <== circuitId;
    weightCalc.version <== version;
    
    component finalWeight = Multiplier();
    finalWeight.in[0] <== weightCalc.baseWeight;
    finalWeight.in[1] <== validFlag;
    weight <== finalWeight.out;
}

/*
 * Helper template: Combination mode selector
 */
template CombinationModeSelector(MAX_PROOFS, PROOF_SIZE) {
    signal input mode;
    signal input validFlags[MAX_PROOFS];
    signal input weightedProofs[MAX_PROOFS][PROOF_SIZE];
    signal input publicInputs[MAX_PROOFS][PROOF_SIZE];
    signal output combinedProof[PROOF_SIZE];
    signal output combinedPublicInputs[PROOF_SIZE];
    
    // Mode 1: Simple aggregation (sum weighted proofs)
    // Mode 2: Batch verification (parallel verification)
    // Mode 3: Recursive verification (nested proofs)
    
    component modeProcessor = ModeProcessor(MAX_PROOFS, PROOF_SIZE);
    modeProcessor.mode <== mode;
    
    for (var i = 0; i < MAX_PROOFS; i++) {
        modeProcessor.validFlags[i] <== validFlags[i];
        for (var j = 0; j < PROOF_SIZE; j++) {
            modeProcessor.weightedProofs[i][j] <== weightedProofs[i][j];
            modeProcessor.publicInputs[i][j] <== publicInputs[i][j];
        }
    }
    
    for (var i = 0; i < PROOF_SIZE; i++) {
        combinedProof[i] <== modeProcessor.combinedProof[i];
        combinedPublicInputs[i] <== modeProcessor.combinedPublicInputs[i];
    }
}

/*
 * Helper template: Proof integrity checker
 */
template ProofIntegrityChecker(MAX_PROOFS) {
    signal input proofHashes[MAX_PROOFS];
    signal input verificationResults[MAX_PROOFS];
    signal input validFlags[MAX_PROOFS];
    signal output integrityValid;
    
    // Check integrity of all proof hashes
    component integrityHash = HashChain(MAX_PROOFS);
    for (var i = 0; i < MAX_PROOFS; i++) {
        integrityHash.values[i] <== proofHashes[i] * verificationResults[i] * validFlags[i];
    }
    
    // Integrity is valid if hash is non-zero
    component integrityCheck = GreaterThan(32);
    integrityCheck.in[0] <== integrityHash.root;
    integrityCheck.in[1] <== 0;
    integrityValid <== integrityCheck.out;
}

/*
 * Helper template: Compression analyzer
 */
template CompressionAnalyzer(MAX_PROOFS, PROOF_SIZE) {
    signal input originalSizes[MAX_PROOFS];
    signal input validFlags[MAX_PROOFS];
    signal input combinedSize;
    signal output ratio;
    
    // Calculate total original size
    component totalOriginal = Sum(MAX_PROOFS);
    for (var i = 0; i < MAX_PROOFS; i++) {
        totalOriginal.values[i] <== originalSizes[i] * validFlags[i];
    }
    
    // Calculate compression ratio
    component ratioCalc = SafeDivision();
    ratioCalc.dividend <== combinedSize * 100; // Percentage
    ratioCalc.divisor <== totalOriginal.out + 1; // Avoid division by zero
    ratio <== ratioCalc.quotient;
}

/*
 * Helper template: Final verification check
 */
template FinalVerificationCheck(MAX_PROOFS) {
    signal input individualResults[MAX_PROOFS];
    signal input validFlags[MAX_PROOFS];
    signal input integrityValid;
    signal input batchSize;
    signal output overallResult;
    
    // All individual verifications must pass
    component allValid = AND(MAX_PROOFS);
    for (var i = 0; i < MAX_PROOFS; i++) {
        component validResult = OR();
        validResult.in[0] <== 1 - validFlags[i]; // Not included
        validResult.in[1] <== individualResults[i]; // Or valid
        allValid.in[i] <== validResult.out;
    }
    
    // Overall result requires all individual results + integrity + non-empty batch
    component finalResult = AND();
    finalResult.in[0] <== allValid.out;
    finalResult.in[1] <== integrityValid;
    
    component nonEmptyBatch = GreaterThan(16);
    nonEmptyBatch.in[0] <== batchSize;
    nonEmptyBatch.in[1] <== 0;
    
    component overallCheck = AND();
    overallCheck.in[0] <== finalResult.out;
    overallCheck.in[1] <== nonEmptyBatch.out;
    overallResult <== overallCheck.out;
} 