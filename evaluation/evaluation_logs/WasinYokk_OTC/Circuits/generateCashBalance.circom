pragma circom 2.0.0;

include "circomlib-master/circuits/poseidon.circom";

template generateCashBalance() {

    // Private Input 
    signal input userID; // UserID //
    signal input totalCash; // Cash //
    signal input cashSalt; // Salt //

    // Output 
    signal output cashBalance;

    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== userID; 
    poseidon.inputs[1] <== totalCash;
    poseidon.inputs[2] <== cashSalt;

    cashBalance <== poseidon.out;
}

component main = generateCashBalance();