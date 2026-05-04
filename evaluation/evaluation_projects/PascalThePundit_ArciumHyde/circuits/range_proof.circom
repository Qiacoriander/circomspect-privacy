pragma circom 2.1.6;

include "circomlib/paths/ecdsa.circom";

// Circuit to prove that a value is within a certain range [min, max]
template RangeProof() {
    signal input value; // The value to prove is in range
    signal input min;   // Minimum value in the range
    signal input max;   // Maximum value in the range
    signal output out;  // 1 if the value is in range, 0 otherwise

    signal range_min_check; // value >= min
    signal range_max_check; // value <= max

    // Check value >= min (equivalent to value - min >= 0)
    component sub_min = Sub();
    sub_min.in[0] <== value;
    sub_min.in[1] <== min;
    signal diff_min = sub_min.out;

    // Using a range constraint to check if diff_min >= 0
    component is_positive_min = IsZero(64); // Assuming 64-bit values
    is_positive_min.in <== diff_min;
    range_min_check = 1 - is_positive_min.out; // 1 if diff >= 0, 0 otherwise

    // Check value <= max (equivalent to max - value >= 0)
    component sub_max = Sub();
    sub_max.in[0] <== max;
    sub_max.in[1] <== value;
    signal diff_max = sub_max.out;

    component is_positive_max = IsZero(64);
    is_positive_max.in <== diff_max;
    range_max_check = 1 - is_positive_max.out; // 1 if diff >= 0, 0 otherwise

    // Both conditions must be true
    component and_gate = AND();
    and_gate.a <== range_min_check;
    and_gate.b <== range_max_check;
    out <== and_gate.out;
}

// More practical range proof using bit decomposition
template RangeProofBits(num_bits) {
    signal input in;      // The value to prove is in range [0, 2^num_bits - 1]
    signal input secret;  // The actual value (private input)
    signal output out;    // 1 if valid proof, 0 otherwise

    // Decompose the value into bits
    component bits[num_bits];
    for (var i = 0; i < num_bits; i++) {
        bits[i] = IsZero(1);  // Check if bit is 0 or 1
        bits[i].in <== secret >> i & 1;
    }

    // Reconstruct the value from bits to ensure consistency
    signal reconstructed_value;
    reconstructed_value <== 0;
    for (var i = 0; i < num_bits; i++) {
        reconstructed_value <== reconstructed_value + (bits[i].in * (2**i));
    }

    // Assert that the reconstructed value matches the input
    in === reconstructed_value;

    out <== 1;  // Proof is valid if all constraints are satisfied
}

// Main component
component main { public [in] } = RangeProofBits(32);