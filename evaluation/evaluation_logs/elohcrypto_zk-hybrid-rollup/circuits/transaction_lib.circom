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
    component senderMerkle = MerkleTree(nLevels);
    senderMerkle.leaves[0] <== senderLeaf;
    for (var i = 1; i < 2**nLevels; i++) {
        senderMerkle.leaves[i] <== senderPathElements[i];
    }
    senderRoot <== senderMerkle.root;

    // Verify receiver UTXO in Merkle tree
    component receiverMerkle = MerkleTree(nLevels);
    receiverMerkle.leaves[0] <== receiverLeaf;
    for (var i = 1; i < 2**nLevels; i++) {
        receiverMerkle.leaves[i] <== receiverPathElements[i];
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