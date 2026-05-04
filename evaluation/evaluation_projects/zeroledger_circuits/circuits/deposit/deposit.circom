pragma circom 2.1.4;

include "poseidon.circom";
include "comparators.circom";

template Deposit(maxInputs) {
    // Public inputs
    signal input hashes[maxInputs]; // poseidon hashes of {amount, s}
    signal input totalAmount; // uint240 total amount
    
    // Private inputs
    signal input amounts[maxInputs]; // uint240 amounts
    signal input sValues[maxInputs]; // bytes32 s values

    // Components
    component hashers[maxInputs]; // poseidon hashers
    component nonNegChecks[maxInputs]; // non-negativity checks
    
    // Efficient sum calculation
    var sum = 0;

    // Validate each input
    for (var i = 0; i < maxInputs; i++) {
        // 1. Validate hash[i] = poseidon_hash({amount[i], s[i]})
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== amounts[i];
        hashers[i].inputs[1] <== sValues[i];
        hashes[i] === hashers[i].out;
        
        // 2. Ensure amount >= 0 (non-negativity check)
        nonNegChecks[i] = GreaterEqThan(240);
        nonNegChecks[i].in[0] <== amounts[i];
        nonNegChecks[i].in[1] <== 0;
        nonNegChecks[i].out === 1; // amount >= 0
        
        // 3. Accumulate sum efficiently
        sum += amounts[i];
    }
    
    // Validate that the computed sum matches the expected total
    sum === totalAmount;
}

component main {public [hashes, totalAmount]} = Deposit(3);