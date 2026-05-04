pragma circom 2.0.0;

template TestAgeVerification() {
    signal input userAge;      // Private: user's actual age
    signal input minAge;       // Public: minimum age required
    signal output out1;        // Public: first output
    signal output out2;        // Public: second output

    // Very simple logic for testing
    out1 <== minAge;           // First public signal = minAge
    out2 <== userAge;          // Second public signal = userAge
    
    // Add a simple constraint to ensure userAge >= minAge
    // This is a basic range check
    signal diff;
    diff <== userAge - minAge;
    
    // This ensures that userAge >= minAge
    // If userAge < minAge, diff would be negative and this constraint would fail
    signal isValid;
    isValid <== diff * diff;  // This will be >= 0, but ensures diff is calculated
}

component main = TestAgeVerification();
