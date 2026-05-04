pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "./merkleProof.circom";
include "./keyPair.circom";


// UTXO { rate, startTime, stopTime, checkpointTime,
//        senderPubKey, receiverPubKey, blinding }
// commitment = hash(UTXO)
// nullifier = hash(commitment, merklePath)

template Revoke(nLevels, zeroLeaf) {
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
    signal input inSenderPrivateKey;
    signal input inReceiverPublicKey;
    signal input inBlinding; 
    
    signal input inputNullifier; 
    signal input inPathIndices; 
    signal input inPathElements[nLevels]; 

    // ===========================================
    // OUTPUT UTXO SIGNALS
    // ===========================================
    // This is moved at an early time to end stream
    // Checked at contract for some future time (i.e. outStopTime >= block.timestamp)
    // Assumed to be > inCheckpointTime as well as inStartTime
    signal input outStopTime;
    signal input outBlinding;
    signal input outputCommitment;

    // ===========================================
    // VERIFY TIMESTAMPS
    // ===========================================
    // Asserts outStopTime < inStopTime
    component isLt = LessThan(64);
    isLt.in[0] <== outStopTime;
    isLt.in[1] <== inStopTime;
    isLt.out === 1;

    // ===========================================
    // VERIFY AMOUNT
    // ===========================================
    publicAmount === (inStopTime - outStopTime) * inRate;

    // ===========================================
    // VERIFY CORRECTNESS OF INPUT UTXO
    // ===========================================
    component inSenderKeyPair = KeyPair();
    inSenderKeyPair.privateKey <== inSenderPrivateKey;

    component inCommitmentHasher = Poseidon(7);
    inCommitmentHasher.inputs[0] <== inRate;
    inCommitmentHasher.inputs[1] <== inStartTime;
    inCommitmentHasher.inputs[2] <== inStopTime;
    inCommitmentHasher.inputs[3] <== inCheckpointTime;
    inCommitmentHasher.inputs[4] <== inSenderKeyPair.publicKey;
    inCommitmentHasher.inputs[5] <== inReceiverPublicKey;
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
    outCommitmentHasher.inputs[2] <== outStopTime;
    outCommitmentHasher.inputs[3] <== inCheckpointTime;
    outCommitmentHasher.inputs[4] <== inSenderKeyPair.publicKey;
    outCommitmentHasher.inputs[5] <== inReceiverPublicKey;
    outCommitmentHasher.inputs[6] <== outBlinding;
    outCommitmentHasher.out === outputCommitment;

    // optional safety constraint to make sure extDataHash cannot be changed
    signal extDataSquare <== extDataHash * extDataHash;
}

component main { public [root, publicAmount, extDataHash, inputNullifier, outStopTime, outputCommitment] } = Revoke(20, 11850551329423159860688778991827824730037759162201783566284850822760196767874);