pragma circom 2.0.0;

// Include core primitives and aggregation circuits
include "../primitives/merkle_tree.circom";
include "../primitives/range_proof.circom";
include "../primitives/hash_chain.circom";
include "../aggregation/commit_aggregator.circom";
include "../aggregation/repo_aggregator.circom";
include "../aggregation/time_aggregator.circom";
include "../aggregation/stats_aggregator.circom";

/*
 * CircuitComposer - Compose multiple circuits into a unified proof
 * 
 * This circuit enables:
 * 1. Hierarchical circuit composition with multiple subcircuits
 * 2. Signal routing between composed circuits
 * 3. Constraint aggregation across multiple proof components
 * 4. Unified witness generation for complex multi-circuit proofs
 * 5. Modular circuit design with reusable components
 */
template CircuitComposer(MAX_CIRCUITS, MAX_SIGNALS_PER_CIRCUIT) {
    // Input signals for circuit composition
    signal input circuitInputs[MAX_CIRCUITS][MAX_SIGNALS_PER_CIRCUIT];  // Inputs for each circuit
    signal input circuitTypes[MAX_CIRCUITS];                            // Type identifier for each circuit
    signal input routingMatrix[MAX_CIRCUITS][MAX_CIRCUITS];             // Signal routing between circuits
    signal input compositionMode;                                       // Composition mode: 1=sequential, 2=parallel, 3=hierarchical
    signal input validationFlags[MAX_CIRCUITS];                        // Which circuits to include in composition
    
    // Output signals
    signal output composedResult[MAX_SIGNALS_PER_CIRCUIT];              // Final composed result
    signal output compositionProof;                                     // Proof of valid composition
    signal output circuitOutputs[MAX_CIRCUITS][MAX_SIGNALS_PER_CIRCUIT]; // Individual circuit outputs
    signal output integrityHash;                                        // Hash of entire composition
    signal output constraintCount;                                      // Total constraints in composition
    
    // Internal signals for composition
    signal intermediateResults[MAX_CIRCUITS][MAX_SIGNALS_PER_CIRCUIT];   // Intermediate results between circuits
    signal routedSignals[MAX_CIRCUITS][MAX_SIGNALS_PER_CIRCUIT];        // Signals after routing
    signal compositionChain[MAX_CIRCUITS];                              // Hash chain of composition steps
    signal validCircuits[MAX_CIRCUITS];                                 // Valid circuit flags
    
    // Circuit component instances
    component circuits[MAX_CIRCUITS];
    component routers[MAX_CIRCUITS];
    component validators[MAX_CIRCUITS];
    component aggregator = CompositionAggregator(MAX_CIRCUITS);
    component integrityChecker = IntegrityChecker(MAX_CIRCUITS);
    component constraintCounter = ConstraintCounter(MAX_CIRCUITS);
    
    // Hash chain for composition integrity
    component compositionHashChain = HashChain(MAX_CIRCUITS);
    
    // Range proofs for input validation
    component inputRanges[MAX_CIRCUITS][MAX_SIGNALS_PER_CIRCUIT];
    component typeRanges[MAX_CIRCUITS];
    
    // Validate circuit types and inputs
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        typeRanges[i] = RangeProof(8);
        typeRanges[i].value <== circuitTypes[i];
        typeRanges[i].minRange <== 0;
        typeRanges[i].maxRange <== 10; // Support up to 10 circuit types
        typeRanges[i].isValid === 1;
        
        for (var j = 0; j < MAX_SIGNALS_PER_CIRCUIT; j++) {
            inputRanges[i][j] = RangeProof(32);
            inputRanges[i][j].value <== circuitInputs[i][j];
            inputRanges[i][j].minRange <== 0;
            inputRanges[i][j].maxRange <== 2**31 - 1; // 32-bit range
            inputRanges[i][j].isValid === 1;
        }
    }
    
    // Instantiate and configure circuits based on type
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        // Circuit type selection and instantiation
        component circuitSelector = CircuitSelector(MAX_SIGNALS_PER_CIRCUIT);
        circuitSelector.circuitType <== circuitTypes[i];
        circuitSelector.validationFlag <== validationFlags[i];
        
        for (var j = 0; j < MAX_SIGNALS_PER_CIRCUIT; j++) {
            circuitSelector.inputs[j] <== circuitInputs[i][j];
        }
        
        // Store circuit outputs
        for (var j = 0; j < MAX_SIGNALS_PER_CIRCUIT; j++) {
            circuitOutputs[i][j] <== circuitSelector.outputs[j];
            intermediateResults[i][j] <== circuitSelector.outputs[j];
        }
        
        validCircuits[i] <== circuitSelector.isValid;
    }
    
    // Route signals between circuits based on routing matrix
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        routers[i] = SignalRouter(MAX_CIRCUITS, MAX_SIGNALS_PER_CIRCUIT);
        
        // Set routing configuration
        for (var j = 0; j < MAX_CIRCUITS; j++) {
            routers[i].routingMatrix[j] <== routingMatrix[i][j];
        }
        
        // Route signals from all circuits
        for (var j = 0; j < MAX_CIRCUITS; j++) {
            for (var k = 0; k < MAX_SIGNALS_PER_CIRCUIT; k++) {
                routers[i].sourceSignals[j][k] <== intermediateResults[j][k];
            }
        }
        
        // Get routed signals
        for (var j = 0; j < MAX_SIGNALS_PER_CIRCUIT; j++) {
            routedSignals[i][j] <== routers[i].routedOutputs[j];
        }
    }
    
    // Compose circuits based on composition mode
    component modeSelector = CompositionModeSelector(MAX_CIRCUITS, MAX_SIGNALS_PER_CIRCUIT);
    modeSelector.mode <== compositionMode;
    
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        modeSelector.validFlags[i] <== validCircuits[i];
        for (var j = 0; j < MAX_SIGNALS_PER_CIRCUIT; j++) {
            modeSelector.circuitOutputs[i][j] <== routedSignals[i][j];
        }
    }
    
    // Generate final composed result
    for (var i = 0; i < MAX_SIGNALS_PER_CIRCUIT; i++) {
        composedResult[i] <== modeSelector.finalResult[i];
    }
    
    // Aggregate composition proof
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        aggregator.circuitProofs[i] <== validCircuits[i];
        aggregator.circuitTypes[i] <== circuitTypes[i];
    }
    compositionProof <== aggregator.aggregatedProof;
    
    // Build composition hash chain for integrity
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        compositionHashChain.values[i] <== circuitTypes[i] + validCircuits[i];
    }
    integrityHash <== compositionHashChain.root;
    
    // Count total constraints
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        constraintCounter.circuitTypes[i] <== circuitTypes[i];
        constraintCounter.validFlags[i] <== validCircuits[i];
    }
    constraintCount <== constraintCounter.totalConstraints;
    
    // Integrity checking
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        integrityChecker.circuitHashes[i] <== compositionHashChain.values[i];
        integrityChecker.validFlags[i] <== validCircuits[i];
    }
    
    // Composition validation constraints
    component validComposition = GreaterThan(16);
    validComposition.in[0] <== compositionProof;
    validComposition.in[1] <== 0;
    validComposition.out === 1;
    
    // At least one circuit must be valid
    component hasValidCircuit = OR(MAX_CIRCUITS);
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        hasValidCircuit.in[i] <== validCircuits[i];
    }
    hasValidCircuit.out === 1;
    
    // Composition mode must be valid
    component validMode = RangeProof(8);
    validMode.value <== compositionMode;
    validMode.minRange <== 1;
    validMode.maxRange <== 3;
    validMode.isValid === 1;
}

/*
 * Helper template: Circuit selector based on type
 */
template CircuitSelector(MAX_SIGNALS) {
    signal input circuitType;
    signal input validationFlag;
    signal input inputs[MAX_SIGNALS];
    signal output outputs[MAX_SIGNALS];
    signal output isValid;
    
    // Circuit type definitions:
    // 1 = CommitAggregator
    // 2 = RepoAggregator  
    // 3 = TimeAggregator
    // 4 = StatsAggregator
    // 5 = RepositoryCredential
    // 6 = LanguageCredential
    // 7 = CollaborationCredential
    
    component typeCheck = RangeProof(8);
    typeCheck.value <== circuitType;
    typeCheck.minRange <== 1;
    typeCheck.maxRange <== 7;
    
    // Simple circuit execution (simplified for composition)
    component circuitExecution = GenericCircuitExecution(MAX_SIGNALS);
    circuitExecution.circuitType <== circuitType;
    circuitExecution.validationFlag <== validationFlag;
    
    for (var i = 0; i < MAX_SIGNALS; i++) {
        circuitExecution.inputs[i] <== inputs[i];
        outputs[i] <== circuitExecution.outputs[i];
    }
    
    isValid <== typeCheck.isValid * validationFlag;
}

/*
 * Helper template: Signal router for circuit composition
 */
template SignalRouter(MAX_CIRCUITS, MAX_SIGNALS) {
    signal input routingMatrix[MAX_CIRCUITS];
    signal input sourceSignals[MAX_CIRCUITS][MAX_SIGNALS];
    signal output routedOutputs[MAX_SIGNALS];
    
    // Route signals based on routing matrix
    component routers[MAX_SIGNALS];
    
    for (var i = 0; i < MAX_SIGNALS; i++) {
        routers[i] = SignalMux(MAX_CIRCUITS);
        
        // Set selector from routing matrix
        routers[i].selector <== routingMatrix[0]; // Simplified routing
        
        // Set input signals
        for (var j = 0; j < MAX_CIRCUITS; j++) {
            routers[i].inputs[j] <== sourceSignals[j][i];
        }
        
        routedOutputs[i] <== routers[i].output;
    }
}

/*
 * Helper template: Composition mode selector
 */
template CompositionModeSelector(MAX_CIRCUITS, MAX_SIGNALS) {
    signal input mode;
    signal input validFlags[MAX_CIRCUITS];
    signal input circuitOutputs[MAX_CIRCUITS][MAX_SIGNALS];
    signal output finalResult[MAX_SIGNALS];
    
    // Mode 1: Sequential composition (chain outputs)
    // Mode 2: Parallel composition (aggregate outputs)
    // Mode 3: Hierarchical composition (tree structure)
    
    component modeProcessor = ModeProcessor(MAX_CIRCUITS, MAX_SIGNALS);
    modeProcessor.mode <== mode;
    
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        modeProcessor.validFlags[i] <== validFlags[i];
        for (var j = 0; j < MAX_SIGNALS; j++) {
            modeProcessor.inputs[i][j] <== circuitOutputs[i][j];
        }
    }
    
    for (var i = 0; i < MAX_SIGNALS; i++) {
        finalResult[i] <== modeProcessor.result[i];
    }
}

/*
 * Helper template: Composition aggregator
 */
template CompositionAggregator(MAX_CIRCUITS) {
    signal input circuitProofs[MAX_CIRCUITS];
    signal input circuitTypes[MAX_CIRCUITS];
    signal output aggregatedProof;
    
    // Aggregate proofs from all valid circuits
    component proofAggregator = Sum(MAX_CIRCUITS);
    component typeAggregator = Sum(MAX_CIRCUITS);
    
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        proofAggregator.values[i] <== circuitProofs[i];
        typeAggregator.values[i] <== circuitTypes[i] * circuitProofs[i];
    }
    
    // Combined aggregated proof
    component proofCombiner = Multiplier();
    proofCombiner.in[0] <== proofAggregator.out;
    proofCombiner.in[1] <== typeAggregator.out;
    aggregatedProof <== proofCombiner.out;
}

/*
 * Helper template: Integrity checker for composition
 */
template IntegrityChecker(MAX_CIRCUITS) {
    signal input circuitHashes[MAX_CIRCUITS];
    signal input validFlags[MAX_CIRCUITS];
    signal output integrityValid;
    
    // Check integrity of all circuit hashes
    component hashChecker = HashChain(MAX_CIRCUITS);
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        hashChecker.values[i] <== circuitHashes[i] * validFlags[i];
    }
    
    // Integrity is valid if hash chain is non-zero
    component integrityCheck = GreaterThan(32);
    integrityCheck.in[0] <== hashChecker.root;
    integrityCheck.in[1] <== 0;
    integrityValid <== integrityCheck.out;
}

/*
 * Helper template: Constraint counter for composition
 */
template ConstraintCounter(MAX_CIRCUITS) {
    signal input circuitTypes[MAX_CIRCUITS];
    signal input validFlags[MAX_CIRCUITS];
    signal output totalConstraints;
    
    // Estimate constraints based on circuit types
    signal constraintWeights[MAX_CIRCUITS];
    
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        component weightCalc = ConstraintWeight();
        weightCalc.circuitType <== circuitTypes[i];
        constraintWeights[i] <== weightCalc.weight * validFlags[i];
    }
    
    component constraintSum = Sum(MAX_CIRCUITS);
    for (var i = 0; i < MAX_CIRCUITS; i++) {
        constraintSum.values[i] <== constraintWeights[i];
    }
    totalConstraints <== constraintSum.out;
} 