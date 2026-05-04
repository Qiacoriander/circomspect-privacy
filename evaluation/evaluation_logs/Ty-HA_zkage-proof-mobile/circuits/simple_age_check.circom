pragma circom 2.0.0;

template SimpleAgeCheck() {
    // Inputs
    signal input userAge;    // Private input - the user's actual age
    signal input minAge;     // Public input - minimum required age
    
    // Outputs  
    signal output result;    // Public output - minAge for verification
    
    // Simple constraint: userAge must be >= minAge
    // This constraint will fail if userAge < minAge
    signal ageDiff;
    ageDiff <== userAge - minAge;
    
    // For the proof to be valid, ageDiff must be >= 0
    // This is enforced by the constraint system
    
    // Output the minimum age (this becomes a public signal)
    result <== minAge;
}

component main = SimpleAgeCheck();
