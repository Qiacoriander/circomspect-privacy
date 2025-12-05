pragma circom 2.0.0;

// Test case: Deduplication mechanism
// Expected: Only 2 unique bit extractions counted (not 4)
template DeduplicationTest() {
    signal private input secret;
    signal output out[4];
    
    // Same bit extraction (bit 0) appears 3 times
    // Should only count as 1 leak due to deduplication
    out[0] <-- secret & 1;
    out[1] <-- secret & 1;  // Duplicate, should not be counted again
    out[2] <-- secret & 1;  // Duplicate again
    
    // Different bit extraction (bit 1)
    // Counts as separate leak
    out[3] <-- (secret >> 1) & 1;
    
    // Total unique leaks: 2 bits (bit 0 + bit 1)
    // Not 4 bits (deduplication working)
    // L(x) = 2 < T(x) = 8, no quantified report
}

component main = DeduplicationTest();
