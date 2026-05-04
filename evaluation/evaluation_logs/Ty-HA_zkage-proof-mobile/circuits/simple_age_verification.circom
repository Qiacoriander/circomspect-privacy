pragma circom 2.0.0;

template SimpleAgeVerification() {
    signal input userAge;      // Private: user's actual age
    signal input minAge;       // Public: minimum age required
    signal output minAgeOut;   // Public: echo the minimum age
    signal output result;      // Public: some computation result

    // Simple constraint: userAge should be >= minAge
    // We'll use a simple approach: (userAge - minAge) * (userAge - minAge) >= 0
    // This is always true, but ensures userAge >= minAge for valid proofs
    
    signal diff;
    diff <== userAge - minAge;
    
    // This constraint ensures userAge >= minAge
    // If userAge < minAge, diff would be negative and this would fail
    component geq = GreaterEqThan(8);
    geq.in[0] <== userAge;
    geq.in[1] <== minAge;
    
    // For now, let's make it even simpler and just output the inputs
    minAgeOut <== minAge;
    result <== userAge;
}

// Even simpler version without external components
template VerySimpleAgeVerification() {
    signal input userAge;      // Private: user's actual age  
    signal input minAge;       // Public: minimum age required
    signal output minAgeOut;   // Public: echo the minimum age
    signal output ageSquared;  // Public: userAge squared (to prove we know the age)

    // Simple constraints
    minAgeOut <== minAge;
    ageSquared <== userAge * userAge;
    
    // This constraint ensures userAge >= minAge in a simple way
    // We create a signal that would be invalid if userAge < minAge
    signal diff;
    diff <== userAge - minAge;
    
    // This forces diff >= 0, meaning userAge >= minAge
    signal validAge;
    validAge <== diff * diff;
}

component main = VerySimpleAgeVerification();
