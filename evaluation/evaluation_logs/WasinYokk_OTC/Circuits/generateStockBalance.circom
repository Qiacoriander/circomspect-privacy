pragma circom 2.0.0;

include "circomlib-master/circuits/poseidon.circom";

template generateStockBalance() {
    
    // Private Input 
    signal input userID; // UserID //
    signal input stockName; // The stockName represent by number //
    signal input totalStock; // The total stock number //
    signal input stockSalt; // Salt
    
    // Output
    signal output stockBalance; 

    component poseidon = Poseidon(4); // Create a component for Poseidon Hash function and Indicate the number of input

    // Indicate the sequence of the input feeding to the Poseidon Hash //
    poseidon.inputs[0] <== userID;
    poseidon.inputs[1] <== stockName;
    poseidon.inputs[2] <== totalStock;
    poseidon.inputs[3] <== stockSalt;

    stockBalance <== poseidon.out;
}

component main = generateStockBalance();