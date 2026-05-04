// tokenPrivacy.circom
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template TokenTransferCommitment() {
    signal input amount;          // Transfer amount
    signal input sender;          // Sender address
    signal input recipient;       // Recipient address
    signal input tokenId;         // Token identifier
    signal input nonce;           // Random nonce
    signal output commitment;     // Transfer commitment

    // Create commitment for token transfer
    component commitmentHasher = Poseidon(5);
    commitmentHasher.inputs[0] <== amount;
    commitmentHasher.inputs[1] <== sender;
    commitmentHasher.inputs[2] <== recipient;
    commitmentHasher.inputs[3] <== tokenId;
    commitmentHasher.inputs[4] <== nonce;

    commitment <== commitmentHasher.out;
}

template TokenPrivacy() {
    // Private inputs
    signal private input amount;          // Transfer amount
    signal private input sender;          // Sender address
    signal private input recipient;       // Recipient address
    signal private input tokenId;         // Token identifier
    signal private input nonce;           // Random nonce
    signal private input senderBalance;   // Current sender balance
    
    // Public inputs
    signal input maxAmount;               // Maximum allowed transfer amount
    signal input minAmount;               // Minimum allowed transfer amount
    
    // Outputs
    signal output commitment;             // Public commitment
    signal output nullifier;              // Nullifier for double-spend prevention
    
    // Verify amount is within allowed range
    component gtMin = GreaterThan(252);
    gtMin.in[0] <== amount;
    gtMin.in[1] <== minAmount;
    gtMin.out === 1;

    component ltMax = LessThan(252);
    ltMax.in[0] <== amount;
    ltMax.in[1] <== maxAmount;
    ltMax.out === 1;

    // Verify sender has sufficient balance
    component balCheck = GreaterThan(252);
    balCheck.in[0] <== senderBalance;
    balCheck.in[1] <== amount;
    balCheck.out === 1;

    // Verify sender and recipient are different
    component neq = IsEqual();
    neq.in[0] <== sender;
    neq.in[1] <== recipient;
    neq.out === 0;

    // Create transfer commitment
    component transferCommit = TokenTransferCommitment();
    transferCommit.amount <== amount;
    transferCommit.sender <== sender;
    transferCommit.recipient <== recipient;
    transferCommit.tokenId <== tokenId;
    transferCommit.nonce <== nonce;

    commitment <== transferCommit.commitment;

    // Generate nullifier
    component nullifierHasher = Poseidon(4);
    nullifierHasher.inputs[0] <== sender;
    nullifierHasher.inputs[1] <== amount;
    nullifierHasher.inputs[2] <== tokenId;
    nullifierHasher.inputs[3] <== nonce;

    nullifier <== nullifierHasher.out;
}

// Optional: Add batch transfer capability
template BatchTokenPrivacy(numTransfers) {
    signal private input amounts[numTransfers];
    signal private input recipients[numTransfers];
    signal private input nonces[numTransfers];
    signal private input senderBalance;
    signal input tokenId;
    signal input sender;
    
    signal output commitments[numTransfers];
    signal output totalAmount;

    var sum = 0;
    
    // Process each transfer
    for (var i = 0; i < numTransfers; i++) {
        component transfer = TokenPrivacy();
        transfer.amount <== amounts[i];
        transfer.sender <== sender;
        transfer.recipient <== recipients[i];
        transfer.tokenId <== tokenId;
        transfer.nonce <== nonces[i];
        transfer.senderBalance <== senderBalance;
        
        commitments[i] <== transfer.commitment;
        sum += amounts[i];
    }

    totalAmount <== sum;
    
    // Verify total amount doesn't exceed balance
    component totalCheck = GreaterThan(252);
    totalCheck.in[0] <== senderBalance;
    totalCheck.in[1] <== totalAmount;
    totalCheck.out === 1;
}