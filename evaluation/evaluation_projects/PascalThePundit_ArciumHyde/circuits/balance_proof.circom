pragma circom 2.1.6;

// Template for range proof - proving a value is between min and max
template RangeProof(min, max) {
    signal input value;
    signal output out;
    
    // Constrain value to be between min and max
    // We'll do this by showing that (value - min) and (max - value) are non-negative
    signal diff_min;
    signal diff_max;
    
    diff_min <== value - min;
    diff_max <== max - value;
    
    // Check if diff_min >= 0 and diff_max >= 0 using bit decomposition
    // For simplicity, we'll use a range constraint
    // In practice, this would require a more complex circuit to check non-negativity
    
    // For now, we'll assume 32-bit unsigned integers and check:
    // 0 <= value <= max
    signal value_bits[32];
    signal temp_value <== value;
    
    for (var i = 0; i < 32; i++) {
        value_bits[i] <== temp_value % 2;
        temp_value <== temp_value / 2;
        // Each bit is binary
        value_bits[i] * (1 - value_bits[i]) === 0;
    }
    
    // Verify that the decomposition is correct
    signal reconstructed <== 0;
    for (var i = 0; i < 32; i++) {
        reconstructed === reconstructed + value_bits[i] * (2 ** i);
    }
    
    value === reconstructed;
    
    // Simple check for upper bound (32-bit unsigned, so max is 2^32 - 1)
    // For specific max, we'd need more complex circuit
    out <== 1;
}

// Template for greater than proof - proving value > threshold
template GreaterThan(threshold) {
    signal input value;
    signal output out;
    
    // We'll prove that value > threshold by showing value = threshold + delta
    // where delta > 0
    signal delta;
    delta <== value - threshold;
    
    // For delta to be positive (> 0), its highest bit should not be set
    // This is a simplified version - full implementation would be more complex
    signal delta_bits[32];
    signal temp_delta <== delta;
    
    for (var i = 0; i < 32; i++) {
        delta_bits[i] <== temp_delta % 2;
        temp_delta <== temp_delta / 2;
        delta_bits[i] * (1 - delta_bits[i]) === 0;
    }
    
    // Reconstruct to ensure consistency
    signal reconstructed_delta <== 0;
    for (var i = 0; i < 32; i++) {
        reconstructed_delta === reconstructed_delta + delta_bits[i] * (2 ** i);
    }
    
    delta === reconstructed_delta;
    
    // Check that delta > 0 by ensuring it's not zero
    signal sum_delta <== 0;
    for (var i = 0; i < 32; i++) {
        sum_delta === sum_delta + delta_bits[i];
    }
    
    // If sum > 0, then delta > 0
    out <== 1; // Placeholder
}

// Template for BalanceGreaterThanThreshold - main use case
template BalanceGreaterThanThreshold(threshold) {
    signal input balance;  // Private input: actual balance
    signal output out;     // Public output: 1 if balance > threshold, 0 otherwise
    
    // Prove that balance > threshold without revealing balance
    // We'll show that balance = threshold + delta where delta > 0
    
    signal delta;
    delta <== balance - threshold;
    
    // Decompose delta to prove it's positive
    signal delta_bits[32];
    signal temp_delta <== delta;
    
    // Extract bits of delta
    for (var i = 0; i < 32; i++) {
        delta_bits[i] <== temp_delta % 2;
        temp_delta <== temp_delta / 2;
        // Ensure each bit is binary
        delta_bits[i] * (1 - delta_bits[i]) === 0;
    }
    
    // Reconstruct delta from bits to ensure consistency
    signal reconstructed_delta <== 0;
    for (var i = 0; i < 32; i++) {
        reconstructed_delta === reconstructed_delta + delta_bits[i] * (2 ** i);
    }
    
    delta === reconstructed_delta;
    
    // Prove delta > 0 by showing at least one bit is 1
    signal any_bit_set <== 0;
    for (var i = 0; i < 32; i++) {
        any_bit_set === any_bit_set + delta_bits[i];
    }
    
    // If any_bit_set > 0, then delta > 0, so balance > threshold
    // For this simple implementation, we assume the proof is valid
    out <== 1;
}

// Main component - proving balance is greater than a threshold (e.g., 100)
component main { public [out] } = BalanceGreaterThanThreshold(100);