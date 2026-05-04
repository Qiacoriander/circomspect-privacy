// messagePrivacy.circom
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template MessageCommitment() {
    signal input message[32]; // Message as array of 32 bytes
    signal input sender;      // Sender address
    signal input recipient;   // Recipient address
    signal input timestamp;   // Message timestamp
    signal input nonce;       // Random nonce for uniqueness
    signal output commitment; // Message commitment

    // Create Poseidon hash for message
    component messageHasher = Poseidon(32);
    for (var i = 0; i < 32; i++) {
        messageHasher.inputs[i] <== message[i];
    }
    signal messageHash <== messageHasher.out;

    // Create commitment combining all elements
    component commitmentHasher = Poseidon(5);
    commitmentHasher.inputs[0] <== messageHash;
    commitmentHasher.inputs[1] <== sender;
    commitmentHasher.inputs[2] <== recipient;
    commitmentHasher.inputs[3] <== timestamp;
    commitmentHasher.inputs[4] <== nonce;

    commitment <== commitmentHasher.out;
}

template MessagePrivacy() {
    signal private input message[32]; // Encrypted message content
    signal private input sender;      // Sender address
    signal private input recipient;   // Recipient address
    signal private input timestamp;   // Message timestamp
    signal private input nonce;       // Random nonce
    signal input recipientPubKey;     // Recipient's public key
    
    signal output commitment;         // Public commitment
    signal output nullifier;          // Nullifier to prevent double-sending

    // Verify sender and recipient are different
    component neq = IsEqual();
    neq.in[0] <== sender;
    neq.in[1] <== recipient;
    neq.out === 0;

    // Create message commitment
    component messageCommit = MessageCommitment();
    for (var i = 0; i < 32; i++) {
        messageCommit.message[i] <== message[i];
    }
    messageCommit.sender <== sender;
    messageCommit.recipient <== recipient;
    messageCommit.timestamp <== timestamp;
    messageCommit.nonce <== nonce;

    commitment <== messageCommit.commitment;

    // Generate nullifier to prevent replay attacks
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== sender;
    nullifierHasher.inputs[1] <== timestamp;
    nullifierHasher.inputs[2] <== nonce;

    nullifier <== nullifierHasher.out;
}