pragma circom 2.1.4;
include "../node_modules/circomlib/circuits/poseidon.circom";

// The template 'poseidon' will hash 4 input signals using the Poseidon hash function.
// Poseidon is a cryptographic hash function optimized for zero-knowledge proofs.

template poseidon() {

   // Define the input signals
   signal input a;  // First input value
   signal input b;  // Second input value
   signal input c;  // Third input value
   signal input d;  // Fourth input value

   // Define the output signal
   signal output out;  // The resulting hash value

   // Instantiate the Poseidon hash component with an input length of 4
   // Poseidon is a cryptographic hash function specifically designed to be efficient
   // in zk-SNARKs and zk-STARKs. The number 4 indicates that this instance of the Poseidon
   // hash function will take exactly 4 inputs.
   component hash = Poseidon(4);

   // Connect the input signals to the Poseidon hash inputs
   hash.inputs[0] <== a;  // Connect 'a' to the first input of the Poseidon hash function
   hash.inputs[1] <== b;  // Connect 'b' to the second input of the Poseidon hash function
   hash.inputs[2] <== c;  // Connect 'c' to the third input of the Poseidon hash function
   hash.inputs[3] <== d;  // Connect 'd' to the fourth input of the Poseidon hash function

   // Assign the output of the Poseidon hash function to the output signal 'out'
   out <== hash.out;
}

// Instantiate the main component that will execute the 'poseidon' template
component main = poseidon();
