pragma circom 2.1.4;

include "./node_modules/circomlib/circuits/mimcsponge.circom";

// In this exercise, we will learn an important concept related to hashing . There are 2 values a and b. You want to 
// perform computation on these and verify it , but secretly without discovering the values. 
// One way is to hash the 2 values and then store the hash as a reference. 
// There is on problem in this concept , attacker can brute force the 2 variables by comparing the public hash with the resulting hash.
// To overcome this , we use a secret value in the input privately. We hash it with a and b. 

// This way brute force becomes illogical as the cost will increase multifolds for the attacker.


// Input 3 values, a, b and salt. 
// Hash all 3 using mimcsponge as a hashing mechanism. 
// Output the res using 'out'.

template Salt() {
    signal input a;       // The first input value
    signal input b;       // The second input value
    signal input salt;    // The secret salt value

    signal output out;    // The output signal for the hash result

    component mimc = MiMCSponge(220);  // Create a MiMCSponge instance with 220 rounds (standard for MiMC)

    // Set the inputs to the MiMCSponge component
    mimc.ins[0] <== a;
    mimc.ins[1] <== b;
    mimc.ins[2] <== salt;

    // Perform the hash and assign the result to the output
    out <== mimc.outs[0];
}

component main = Salt();
// By default all inputs are private in circom. We will not define any input as public 
// because we want them to be a secret , at least in this case. 

// There will be cases where some values will be declared explicitly public .




