pragma circom 2.0.0;

// Test case: Custom port names (non-standard naming)
// Purpose: Verify that port detection works with arbitrary signal names
// Expected: PartialLeak propagation through custom-named ports

template CustomHasher() {
    signal input message;      // Custom input name (not "in")
    signal output digest;      // Custom output name (not "out")
    
    // Simplified hash: just square the message
    digest <== message * message;
}

template CustomComparator() {
    signal input value_a;      // Custom input names
    signal input value_b;
    signal output result;      // Custom output name
    
    // Simple comparison simulation
    signal diff;
    diff <== value_b - value_a;
    result <== diff;
}

template CustomBitExtractor() {
    signal input data;         // Custom input name
    signal output extracted;   // Custom output name
    
    // Extract lowest bit
    extracted <== data & 1;
}

template MainCircuit() {
    signal input secret;
    signal output hash_output;
    signal output compare_output;
    signal output bit_output;
    
    // Test 1: Hash with custom port names
    component hasher = CustomHasher();
    hasher.message <== secret;           // Access custom input port
    hash_output <== hasher.digest;       // Access custom output port
    
    // Test 2: Comparator with multiple custom inputs
    component comp = CustomComparator();
    comp.value_a <== secret;
    comp.value_b <== 100;
    compare_output <== comp.result;      // Access custom output port
    
    // Test 3: Bit extractor with custom ports
    component extractor = CustomBitExtractor();
    extractor.data <== secret;
    bit_output <== extractor.extracted;  // Should be PartialLeak
}

component main = MainCircuit();
