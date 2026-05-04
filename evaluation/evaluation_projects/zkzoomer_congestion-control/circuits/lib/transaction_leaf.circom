pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// Returns the transaction leaf, which is the hash of the transaction
template TransactionLeaf() {
    signal input fromX;
    signal input fromY;
    signal input toX;
    signal input toY;
    signal input nonce;
    signal input amount;

    signal output out;

    component txLeaf = Poseidon(6);

    txLeaf.inputs[0] <== fromX;
    txLeaf.inputs[1] <== fromY;
    txLeaf.inputs[2] <== toX;
    txLeaf.inputs[3] <== toY;
    txLeaf.inputs[4] <== nonce;
    txLeaf.inputs[5] <== amount;

    out <== txLeaf.out;
}
