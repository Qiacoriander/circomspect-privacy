pragma circom 2.0.0;

// Test case: Multiple outputs with different custom names
// Purpose: Verify correct handling of multiple output ports with custom names
// Expected: Different taint levels based on operations

template MultiOutputProcessor() {
    signal input raw_data;
    signal output processed;    // Tainted (full computation)
    signal output flag;         // PartialLeak (bit extraction)
    signal output hash_result;  // Tainted (multiplication)
    
    // Full processing (Tainted)
    processed <== raw_data * 2 + 5;
    
    // Bit flag extraction (PartialLeak)
    flag <== raw_data & 1;
    
    // Hash-like operation (Tainted)
    hash_result <== raw_data * raw_data;
}

template AdvancedAnalyzer() {
    signal input source;
    signal output analysis_a;
    signal output analysis_b;
    signal output analysis_c;
    
    // Different types of operations
    analysis_a <== source >> 3;         // PartialLeak (shift)
    analysis_b <== (source >> 2) & 1;   // PartialLeak (bit extract)
    analysis_c <== source + 100;        // Tainted (arithmetic)
}

template TestMultipleCustomOutputs() {
    signal input secret_value;
    signal output out_processed;
    signal output out_flag;
    signal output out_hash;
    signal output out_analysis_a;
    signal output out_analysis_b;
    signal output out_analysis_c;
    
    // Component 1: Multi-output processor
    component processor = MultiOutputProcessor();
    processor.raw_data <== secret_value;
    out_processed <== processor.processed;      // Tainted
    out_flag <== processor.flag;                // PartialLeak
    out_hash <== processor.hash_result;         // Tainted
    
    // Component 2: Advanced analyzer
    component analyzer = AdvancedAnalyzer();
    analyzer.source <== secret_value;
    out_analysis_a <== analyzer.analysis_a;     // PartialLeak
    out_analysis_b <== analyzer.analysis_b;     // PartialLeak
    out_analysis_c <== analyzer.analysis_c;     // Tainted
}

component main = TestMultipleCustomOutputs();
