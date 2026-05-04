pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "./merkleProof.circom";
include "./keyPair.circom";

// UTXO { rate, startTime, stopTime, checkpointTime,
//        senderPubKey, receiverPubKey, blinding }
// commitment = hash(UTXO)
// nullifier = hash(commitment, merklePath)

template Withdraw(nLevels, zeroLeaf) {
    signal input root;
    signal input publicAmount; // withdraw amount + fee
    signal input extDataHash;

    // ===========================================
    // INPUT UTXO SIGNALS
    // ===========================================
    signal input inRate; // tokens per sec.
    signal input inStartTime;
    signal input inStopTime;
    signal input inCheckpointTime;
    signal input inSenderPublicKey;
    signal input inReceiverPrivateKey;
    signal input inBlinding; 

    signal input inputNullifier; 
    signal input inPathIndices; 
    signal input inPathElements[nLevels]; 

    // ===========================================
    // OUTPUT UTXO SIGNALS
    // ===========================================
    // Checked by contract for a past timestamp
    signal input outCheckpointTime; 
    signal input outBlinding;
    signal input outputCommitment;


    // ===========================================
    // VERIFY TIMESTAMPS
    // ===========================================
    // Asserts outCheckpointTime > inCheckpointTime
    component isGt = GreaterThan(64);
    isGt.in[0] <== outCheckpointTime;
    isGt.in[1] <== inCheckpointTime;
    isGt.out === 1;

    // Asserts outCheckpointTime <= inStopTime
    component isLtEq = LessEqThan(64);
    isLtEq.in[0] <== outCheckpointTime;
    isLtEq.in[1] <== inStopTime;
    isLtEq.out === 1;

    // ===========================================
    // VERIFY AMOUNT
    // ===========================================
    publicAmount === (outCheckpointTime - inCheckpointTime) * inRate;

    // ===========================================
    // VERIFY CORRECTNESS OF INPUT UTXO
    // ===========================================
    component inReceiverKeyPair = KeyPair();
    inReceiverKeyPair.privateKey <== inReceiverPrivateKey;

    component inCommitmentHasher = Poseidon(7);
    inCommitmentHasher.inputs[0] <== inRate;
    inCommitmentHasher.inputs[1] <== inStartTime;
    inCommitmentHasher.inputs[2] <== inStopTime;
    inCommitmentHasher.inputs[3] <== inCheckpointTime;
    inCommitmentHasher.inputs[4] <== inSenderPublicKey;
    inCommitmentHasher.inputs[5] <== inReceiverKeyPair.publicKey;
    inCommitmentHasher.inputs[6] <== inBlinding;

    // Asserts correctness of nullifier
    component inNullifierHasher = Poseidon(2);
    inNullifierHasher.inputs[0] <== inCommitmentHasher.out;
    inNullifierHasher.inputs[1] <== inPathIndices;
    inNullifierHasher.out === inputNullifier;

    // Asserts existence in tree
    component inTree = MerkleProof(nLevels);
    inTree.leaf <== inCommitmentHasher.out;
    inTree.pathIndices <== inPathIndices;
    for (var i = 0; i < nLevels; i++) {
        inTree.pathElements[i] <== inPathElements[i];
    }
    inTree.root === root;


    // ===========================================
    // VERIFY CORRECTNESS OF OUTPUT UTXO
    // ===========================================
    component outCommitmentHasher = Poseidon(7);
    outCommitmentHasher.inputs[0] <== inRate;
    outCommitmentHasher.inputs[1] <== inStartTime;
    outCommitmentHasher.inputs[2] <== inStopTime;
    outCommitmentHasher.inputs[3] <== outCheckpointTime;
    outCommitmentHasher.inputs[4] <== inSenderPublicKey;
    outCommitmentHasher.inputs[5] <== inReceiverKeyPair.publicKey;
    outCommitmentHasher.inputs[6] <== outBlinding;
    outCommitmentHasher.out === outputCommitment;

    // optional safety constraint to make sure extDataHash cannot be changed
    signal extDataSquare <== extDataHash * extDataHash;
}

component main { public [root, publicAmount, extDataHash, inputNullifier, outCheckpointTime, outputCommitment] } = Withdraw(20, 11850551329423159860688778991827824730037759162201783566284850822760196767874);