pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

template TxLeaf() {
    // Returns the transaction leaf, which is the hash of the transaction:
    // hash(from, to, amount, token_type)

    signal input senderX;
    signal input senderY;
    signal input senderIndex;
    signal input receiverX;
    signal input receiverY;
    signal input nonce;
    signal input amount;
    signal input senderTokenType;

    signal output out;

    component txLeaf = Poseidon(2);
    component leftSubLeaf = Poseidon(4);
    component rightSubLeaf = Poseidon(4);

    leftSubLeaf.inputs[0] <== senderX;
    leftSubLeaf.inputs[1] <== senderY;
    leftSubLeaf.inputs[2] <== receiverX;
    leftSubLeaf.inputs[3] <== receiverY;

    rightSubLeaf.inputs[0] <== senderIndex;
    rightSubLeaf.inputs[1] <== nonce;
    rightSubLeaf.inputs[2] <== amount;
    rightSubLeaf.inputs[3] <== senderTokenType;

    txLeaf.inputs[0] <== leftSubLeaf.out;
    txLeaf.inputs[1] <== rightSubLeaf.out;

    out <== txLeaf.out;
}