pragma circom  2.1.0;

include "./utils.circom";
include "../../../hash_functions/poseidon_personaelabs/circuits/poseidon.circom";


/*
    > circom circuits/rln.circom --r1cs --wasm --sym --c --output ./build 
    
    template instances: 214
    non-linear constraints: 960
    linear constraints: 0
    public inputs: 2
    public outputs: 2
    private inputs: 3
    private outputs: 0
    wires: 964
    labels: 2929
    Written successfully: ./build/rln.r1cs
    Written successfully: ./build/rln.sym
    Written successfully: ./build/rln_cpp/rln.cpp and ./build/rln_cpp/rln.dat
    Written successfully: ./build/rln_cpp/main.cpp, circom.hpp, calcwit.hpp, calcwit.cpp, fr.hpp, fr.cpp, fr.asm and Makefile
    Written successfully: ./build/rln_js/rln.wasm
    Everything went okay, circom safe
*/

// A pure RLN without memebership checker
template RLN(LIMIT_BIT_SIZE) {
    // Private signals
    signal input identitySecret;
    signal input userMessageLimit;
    signal input messageId;

    // Public signals
    signal input x; // Hash(signal), where signal is for example message, that was sent by user;
    signal input externalNullifier; // Poseidon(epoch,rln_identifier), where rln_identifier is a random finite field value, unique per RLN app.

    // Outputs
    signal output y; // calculated first-degree linear polynomial (y=kx+b);
    signal output nullifier; // internal nullifier/pseudonym of the user in anonyomus environment;

    signal identityCommitment <== Poseidon(1)([identitySecret]);
    signal rateCommitment <== Poseidon(2)([identityCommitment, userMessageLimit]);

    // MessageId range check
    RangeCheck(LIMIT_BIT_SIZE)(messageId, userMessageLimit);

    // SSS share calculation
    signal a1 <== Poseidon(3)([identitySecret, externalNullifier, messageId]);
    y <== a1 * x + identitySecret; // A(x) = a1 ∗ x + a0

    // Nullifier Calculation
    nullifier <== Poseidon(1)([a1]);
}
