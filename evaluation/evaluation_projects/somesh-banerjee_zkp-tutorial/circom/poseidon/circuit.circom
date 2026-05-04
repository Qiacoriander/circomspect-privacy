pragma circom 2.1.4;


// Poseidon hash function is a cryptographic hash function that is based on the sponge construction, widely used in zero-knowledge proof systems such as zk-SNARKs. 
// Input 4 variables,namely,'a','b','c','d' , and output variable 'out' .
// Now , hash all the 4 inputs using poseidon and output it . 

include "../node_modules/circomlib/circuits/poseidon.circom";

template poseidon() {
    // the input variables are BigInts
    signal input a, b, c, d;
    // declare a Poseidon component with 4 inputs
    // and there will be 1 output i.e. the hash of the 4 inputs
    signal output out <== Poseidon(4)([a,b,c,d]);
}

component main = poseidon();