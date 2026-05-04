pragma circom 2.0.0;

include "utils/poseidon.circom";
include "./transaction_lib.circom";
include "./utils/merkletree.circom";

template Batch(nLevels, nTransactions) {
    signal input batchId; // Batch identifier
    signal input senderLeaves[nTransactions]; // Sender UTXO hashes
    signal input receiverLeaves[nTransactions]; // Receiver UTXO hashes
    signal input amounts[nTransactions]; // Transaction amounts
    signal input senderPathElements[nTransactions][nLevels]; // Sender Merkle proofs
    signal input senderPathIndices[nTransactions][nLevels]; // Sender path indices
    signal input receiverPathElements[nTransactions][nLevels]; // Receiver Merkle proofs
    signal input receiverPathIndices[nTransactions][nLevels]; // Receiver path indices
    signal input senderNullifiers[nTransactions]; // Sender nullifiers
    signal input receiverBalances[nTransactions]; // Receiver account balances
    signal output batchRoot; // Final Merkle root
    signal output nullifierHashes[nTransactions]; // Hashed nullifiers
    signal output publicBatchId; // Public batch identifier
    
    publicBatchId <== batchId; // Expose batchId as public signal

    // Validate each transaction in the batch
    component transactions[nTransactions];
    for (var i = 0; i < nTransactions; i++) {
        transactions[i] = Transaction(nLevels);
        transactions[i].senderLeaf <== senderLeaves[i];
        transactions[i].receiverLeaf <== receiverLeaves[i];
        transactions[i].amount <== amounts[i];
        for (var j = 0; j < nLevels; j++) {
            transactions[i].senderPathElements[j] <== senderPathElements[i][j];
            transactions[i].senderPathIndices[j] <== senderPathIndices[i][j];
            transactions[i].receiverPathElements[j] <== receiverPathElements[i][j];
            transactions[i].receiverPathIndices[j] <== receiverPathIndices[i][j];
        }
        transactions[i].senderNullifier <== senderNullifiers[i];
        transactions[i].receiverBalance <== receiverBalances[i];
        nullifierHashes[i] <== transactions[i].nullifierHash;
    }

    // Compute final Merkle root (aggregate all transaction outputs)
    component merkleTree = MerkleTree(nLevels);
    for (var i = 0; i < 2**nLevels; i++) {
        merkleTree.leaves[i] <== i < nTransactions ? transactions[i].receiverLeaf : 0;
    }
    batchRoot <== merkleTree.root;
}

component main = Batch(4, 2);
