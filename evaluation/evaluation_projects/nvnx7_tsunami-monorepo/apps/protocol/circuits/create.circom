pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "./merkleProof.circom";
include "./keyPair.circom";

// UTXO { rate, startTime, stopTime, checkpointTime,
//        senderPubKey, receiverPubKey, blinding }
// commitment = hash(UTXO)
// nullifier = hash(commitment, merklePath)

template Create(nLevels, zeroLeaf) {
    signal input publicAmount; // total stream amount

    signal input rate;
    signal input startTime;
    signal input stopTime;
    signal input checkpointTime;
    signal input senderPrivateKey;
    signal input receiverPublicKey;
    signal input blinding; 
    signal input commitment;

    // ===========================================
    // Verify correctness of timestamps
    // ===========================================

    // Assert startTime < stopTime
    component isLt = LessEqThan(64);
    isLt.in[0] <== startTime;
    isLt.in[1] <== stopTime;
    isLt.out === 1;

    // Assert checkpointTime == startTime
    checkpointTime === startTime;

    // ===========================================
    // Verify correctness of amounts
    // ===========================================

    // Assert `publicAmount` must be fully consumed by total duration 
    // at `rate` tokens/sec
    publicAmount === (stopTime - startTime) * rate;

    // ===========================================
    // Verify correctness of commitment
    // ===========================================
    component senderKeyPair = KeyPair();
    component commitmentHasher = Poseidon(7);

    senderKeyPair.privateKey <== senderPrivateKey;

    commitmentHasher.inputs[0] <== rate;
    commitmentHasher.inputs[1] <== startTime;
    commitmentHasher.inputs[2] <== stopTime;
    commitmentHasher.inputs[3] <== checkpointTime;
    commitmentHasher.inputs[4] <== senderKeyPair.publicKey;
    commitmentHasher.inputs[5] <== receiverPublicKey;
    commitmentHasher.inputs[6] <== blinding;

    commitment === commitmentHasher.out;
}

component main { public [publicAmount, commitment] } = Create(20, 11850551329423159860688778991827824730037759162201783566284850822760196767874);