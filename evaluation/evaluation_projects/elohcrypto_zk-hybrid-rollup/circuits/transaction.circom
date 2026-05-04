pragma circom 2.0.0;

include "./utils/custom_comparators.circom";
include "utils/poseidon.circom";
include "./utils/merkletree.circom";

template Transaction(nLevels) {
    signal input senderLeaf; // Sender UTXO hash
    signal input receiverLeaf; // Receiver UTXO hash
    signal input amount; // Transaction amount
    signal input senderPathElements[nLevels]; // Sender Merkle proof
    signal input senderPathIndices[nLevels]; // Sender path indices
    signal input receiverPathElements[nLevels]; // Receiver Merkle proof
    signal input receiverPathIndices[nLevels]; // Receiver path indices
    signal input senderNullifier; // Sender nullifier to prevent double-spending
    signal input receiverBalance; // Receiver's account balance
    signal output senderRoot; // Sender Merkle root
    signal output receiverRoot; // Receiver Merkle root
    signal output nullifierHash; // Hashed nullifier

    // Verify sender UTXO in Merkle tree
    component senderMerkle = MerkleProof(nLevels);
    senderMerkle.leaf <== senderLeaf;
    for (var i = 0; i < nLevels; i++) {
        senderMerkle.pathElements[i] <== senderPathElements[i];
        senderMerkle.pathIndices[i] <== senderPathIndices[i];
    }
    senderRoot <== senderMerkle.root;

    // Verify receiver UTXO in Merkle tree
    component receiverMerkle = MerkleProof(nLevels);
    receiverMerkle.leaf <== receiverLeaf;
    for (var i = 0; i < nLevels; i++) {
        receiverMerkle.pathElements[i] <== receiverPathElements[i];
        receiverMerkle.pathIndices[i] <== receiverPathIndices[i];
    }
    receiverRoot <== receiverMerkle.root;

    // Compute nullifier hash
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== senderLeaf;
    poseidon.inputs[1] <== senderNullifier;
    nullifierHash <== poseidon.out;

    // Verify balance sufficiency (account-based check)
    component geq = GreaterEqThan(252); // 252 bits to handle large balances
    geq.in[0] <== receiverBalance;
    geq.in[1] <== amount;
    geq.out === 1; // Ensure receiverBalance >= amount
}

component main = Transaction(4);

