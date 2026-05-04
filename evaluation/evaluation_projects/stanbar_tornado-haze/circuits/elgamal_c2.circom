pragma circom 2.1.0;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";

/*
    ElGamalC2 is a circuit that constrains the second part of the ElGamal encryption scheme.
    It takes as input a random number, the public key of the recipent and the message.
    It outputs randomness * recipent_public_key + message
*/
template ElGamalC2() {
    signal input random_bits[253];
    signal input recipent_public_key[2];
    signal input message[2];
    signal output out[2];

    // r * P
    signal rP[2] <== EscalarMulAny(253)(p <== recipent_public_key, e <== random_bits);

    // r * P + P_Message
    signal (xout, yout) <== BabyAdd()(x1 <== rP[0], y1 <== rP[1], x2 <== message[0], y2 <== message[1]); 

    out <== [xout, yout];
}