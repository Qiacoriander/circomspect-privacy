pragma circom 2.2.1;
include "../../node_modules/circomlib/circuits/mimc.circom";

template TxLeaf() {

    signal input fromX;
    signal input fromY;
    signal input fromIndex;
    signal input toX;
    signal input toY;
    signal input nonce;
    signal input amount;
    signal input tokenType;
    signal input k; // Thêm đầu vào k
    signal output out;

    log("TxLeaf Hashing Inputs:");
    log("fromX:", fromX);
    log("fromY:", fromY);
    log("fromIndex:", fromIndex);
    log("toX:", toX);
    log("toY:", toY);
    log("nonce:", nonce);
    log("amount:", amount);
    log("tokenType:", tokenType);

    component txLeaf = MultiMiMC7(8,91);
    txLeaf.in[0] <== fromX;
    txLeaf.in[1] <== fromY;
    txLeaf.in[2] <== fromIndex;
    txLeaf.in[3] <== toX;
    txLeaf.in[4] <== toY; 
    txLeaf.in[5] <== nonce;
    txLeaf.in[6] <== amount;
    txLeaf.in[7] <== tokenType;
    txLeaf.k <== 1; // Kết nối đầu vào k
    out <== txLeaf.out;
    log("TxLeaf Hash Output:", out);
}
