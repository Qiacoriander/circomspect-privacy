pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

template MiniMarketV1() {
    // -------- public inputs --------
    signal input marketId;        // binds to a specific market
    signal input msgHash;         // commitment to private message
    signal input marketMsgHash;   // Poseidon(marketId, msgHash)
    signal input outcome;         // 0/1
    signal input nullifier;       // Poseidon(secret, marketId)

    // -------- private inputs --------
    signal input message;         // private data (constrained to 32 bits)
    signal input secret;          // private identity seed (for nullifier)

    // 1) msgHash == Poseidon(message)
    component h1 = Poseidon(1);
    h1.inputs[0] <== message;
    msgHash === h1.out;

    // 2) marketMsgHash == Poseidon(marketId, msgHash)
    component h2 = Poseidon(2);
    h2.inputs[0] <== marketId;
    h2.inputs[1] <== msgHash;
    marketMsgHash === h2.out;

    // 3) outcome == LSB(message), with message constrained to 32 bits
    component bits = Num2Bits(32);
    bits.in <== message;
    outcome === bits.out[0];

    // 4) nullifier == Poseidon(secret, marketId)
    component h3 = Poseidon(2);
    h3.inputs[0] <== secret;
    h3.inputs[1] <== marketId;
    nullifier === h3.out;
}

component main { public [marketId, msgHash, marketMsgHash, outcome, nullifier] } = MiniMarketV1();