pragma circom 2.0.0;

// Minimal circuit using opencircom: hash two inputs and output the result.
include "hashing/poseidon.circom";

template HelloHash() {
    signal input a;
    signal input b;
    signal input out;  // public: claimed hash
    component h = Poseidon(2);
    h.inputs[0] <== a;
    h.inputs[1] <== b;
    h.out === out;
}

component main {public [out]} = HelloHash();
