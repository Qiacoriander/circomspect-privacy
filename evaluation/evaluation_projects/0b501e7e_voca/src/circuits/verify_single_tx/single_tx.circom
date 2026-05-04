pragma circom 2.0.0;

include "./leaf_existence.circom";
include "./eddsa.circom";
include "./get_merkle_root.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template ProcessTx(k) {

    signal input accountsRoot; 

    // intermediate root
    signal input intermediateRoot;

    // account public keys
    signal input accountsPublicKeys[2**k][2];

    // account balances 
    signal input accountBalances[2**k];

    // transaction input
    signal input senderPublicKey[2];
    signal input senderBalance;
    signal input receiverPublicKey[2];
    signal input receiverBalance;
    signal input amount;
    // sender signature
    signal input signatureR8x;
    signal input signatureR8y;
    signal input signatureS;
    // proof of inclusion
    signal input senderProof[k];
    signal input senderProofPositions[k];
    signal input receiverProof[k];
    signal input receiverProofPositions[k];

    // output
    signal output new_accountsRoot;


    component senderExistence = LeafExistence(k, 3);
    senderExistence.preimage[0] <== senderPublicKey[0];
    senderExistence.preimage[1] <== senderPublicKey[1];
    senderExistence.preimage[2] <== senderBalance;
    senderExistence.root <== accountsRoot;
    for (var i = 0; i < k; i++) {
        senderExistence.siblingHashes[i] <== senderProof[i];
        senderExistence.siblingPositions[i] <== senderProofPositions[i];
    }

    component signatureCheck = VerifyEdDSAPoseidon(5);
    signatureCheck.from_x <== senderPublicKey[0];
    signatureCheck.from_y <== senderPublicKey[1];
    signatureCheck.R8x <== signatureR8x;
    signatureCheck.R8y <== signatureR8y;
    signatureCheck.S <== signatureS;
    signatureCheck.preimage[0] <== senderPublicKey[0];
    signatureCheck.preimage[1] <== senderPublicKey[1];
    signatureCheck.preimage[2] <== receiverPublicKey[0];
    signatureCheck.preimage[3] <== receiverPublicKey[1];
    signatureCheck.preimage[4] <== amount;

    component newSenderLeaf = Poseidon(3);
    newSenderLeaf.inputs[0] <== senderPublicKey[0];
    newSenderLeaf.inputs[1] <== senderPublicKey[1];
    newSenderLeaf.inputs[2] <== senderBalance - amount;

    component computedIntermediateRoot = GetMerkleRoot(k);
    
    computedIntermediateRoot.leafNode <== newSenderLeaf.out;
    for (var i = 0; i < k; i++) {
        computedIntermediateRoot.siblingHashes[i] <== senderProof[i];
        computedIntermediateRoot.siblingPositions[i] <== senderProofPositions[i];
    }

    computedIntermediateRoot.merkleRoot === intermediateRoot;


    component receiverExistence = LeafExistence(k, 3);
    receiverExistence.preimage[0] <== receiverPublicKey[0];
    receiverExistence.preimage[1] <== receiverPublicKey[1];
    receiverExistence.preimage[2] <== receiverBalance;
    receiverExistence.root <== intermediateRoot;
    for (var i = 0; i < k; i++) {
        receiverExistence.siblingHashes[i] <== receiverProof[i];
        receiverExistence.siblingPositions[i] <== receiverProofPositions[i];
    }

    component newReceiverLeaf = Poseidon(3);
    newReceiverLeaf.inputs[0] <== receiverPublicKey[0]; 
    newReceiverLeaf.inputs[1] <== receiverPublicKey[1];
    newReceiverLeaf.inputs[2] <== receiverBalance + amount;

    component computed_final_root = GetMerkleRoot(k);
    computed_final_root.leafNode <== newReceiverLeaf.out;
    for (var i = 0; i < k; i++) {
        computed_final_root.siblingHashes[i] <== receiverProof[i];
        computed_final_root.siblingPositions[i] <== receiverProofPositions[i];
    }

    new_accountsRoot <== computed_final_root.merkleRoot;
}

component main {public [accountsRoot]} = ProcessTx(1);