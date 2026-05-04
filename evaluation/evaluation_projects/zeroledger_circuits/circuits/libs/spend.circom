pragma circom 2.1.4;

include "poseidon.circom";
include "comparators.circom";

template Spend(maxInputs, maxOutputs) {
    // Public inputs
    signal input inputs_hashes[maxInputs]; // poseidon hashes of {amount, s}
    signal input outputs_hashes[maxOutputs]; // poseidon hashes of {amount, s}
    signal input fee; // uint240 fee amount
    
    // Private inputs
    signal input input_amounts[maxInputs];
    signal input input_sValues[maxInputs];
    signal input output_amounts[maxOutputs];
    signal input output_sValues[maxOutputs];

    // Components
    component input_hashers[maxInputs]; // poseidon hashers
    component output_hashers[maxOutputs]; // poseidon hashers
    component nonNegChecks[maxOutputs]; // non-negativity checks
    
    // Efficient sum calculation
    var input_sum = 0;
    var output_sum = 0;

    // Validate each input
    for (var i = 0; i < maxInputs; i++) {
        // 1. Validate hash[i] = poseidon_hash({amount[i], s[i]})
        input_hashers[i] = Poseidon(2);
        input_hashers[i].inputs[0] <== input_amounts[i];
        input_hashers[i].inputs[1] <== input_sValues[i];
        inputs_hashes[i] === input_hashers[i].out;
        
        // 2. Accumulate input_sum
        input_sum += input_amounts[i];
    }

    // Validate each output
    for (var i = 0; i < maxOutputs; i++) {
        // 1. Validate hash[i] = poseidon_hash({amount[i], s[i]})
        output_hashers[i] = Poseidon(2);
        output_hashers[i].inputs[0] <== output_amounts[i];
        output_hashers[i].inputs[1] <== output_sValues[i];
        outputs_hashes[i] === output_hashers[i].out;
        
        // 2. Ensure amount >= 0 (non-negativity check)
        nonNegChecks[i] = GreaterEqThan(240);
        nonNegChecks[i].in[0] <== output_amounts[i];
        nonNegChecks[i].in[1] <== 0;
        nonNegChecks[i].out === 1; // amount >= 0
        
        // 3. Accumulate output_sum
        output_sum += output_amounts[i];
    }
    
    input_sum === output_sum + fee;
}