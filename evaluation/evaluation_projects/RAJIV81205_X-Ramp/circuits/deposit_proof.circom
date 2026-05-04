pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsa.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Deposit Attestation Verification Circuit
 * 
 * This circuit proves that a user received a valid signed attestation from an anchor
 * without revealing the signature itself. The attestation contains amount, timestamp,
 * and user address, all signed by the anchor's private key.
 * 
 * Public Inputs:
 * - amount: The deposit amount (public for verification)
 * - user_address_hash: Hash of the user's address (public for verification)
 * - anchor_public_key: The anchor's public key (public for verification)
 * 
 * Private Inputs:
 * - user_address: The actual user address (private)
 * - timestamp: When the attestation was created (private)
 * - signature_r: First part of EdDSA signature (private)
 * - signature_s: Second part of EdDSA signature (private)
 */

template DepositProof() {
    // Public inputs
    signal input amount;                    // Deposit amount (public)
    signal input user_address_hash;         // Hash of user address (public)
    signal input anchor_public_key[2];      // Anchor's EdDSA public key (public)
    
    // Private inputs
    signal input user_address;              // User's address (private)
    signal input timestamp;                 // Attestation timestamp (private)
    signal input signature_r[2];           // EdDSA signature R point (private)
    signal input signature_s;              // EdDSA signature S scalar (private)
    
    // Output signals
    signal output valid;                    // 1 if proof is valid, 0 otherwise
    
    // Internal components
    component poseidon_hash = Poseidon(1);
    component poseidon_message = Poseidon(3);
    component eddsa_verifier = EdDSAVerifier();
    
    // 1. Verify that the provided user_address hashes to user_address_hash
    poseidon_hash.inputs[0] <== user_address;
    user_address_hash === poseidon_hash.out;
    
    // 2. Create the message hash from attestation data
    // Message = Poseidon(amount, timestamp, user_address)
    poseidon_message.inputs[0] <== amount;
    poseidon_message.inputs[1] <== timestamp;
    poseidon_message.inputs[2] <== user_address;
    
    // 3. Verify the EdDSA signature
    eddsa_verifier.enabled <== 1;
    eddsa_verifier.Ax <== anchor_public_key[0];
    eddsa_verifier.Ay <== anchor_public_key[1];
    eddsa_verifier.R8x <== signature_r[0];
    eddsa_verifier.R8y <== signature_r[1];
    eddsa_verifier.S <== signature_s;
    eddsa_verifier.M <== poseidon_message.out;
    
    // 4. Output validity
    valid <== eddsa_verifier.valid;
}

/*
 * Timestamp Validation Template
 * Ensures the timestamp is within a reasonable range (not too old, not in future)
 */
template TimestampValidator(max_age_seconds) {
    signal input timestamp;
    signal input current_time;
    signal output valid;
    
    component lt1 = LessThan(64);  // timestamp < current_time + 300 (5 min future tolerance)
    component lt2 = LessThan(64);  // current_time - max_age < timestamp
    
    // Check timestamp is not too far in the future (5 minutes tolerance)
    lt1.in[0] <== timestamp;
    lt1.in[1] <== current_time + 300;
    
    // Check timestamp is not too old
    lt2.in[0] <== current_time - max_age_seconds;
    lt2.in[1] <== timestamp;
    
    // Both conditions must be true
    valid <== lt1.out * lt2.out;
}

/*
 * Enhanced Deposit Proof with Timestamp Validation
 * Includes timestamp validation to prevent replay attacks
 */
template DepositProofWithTimestamp() {
    // Public inputs
    signal input amount;
    signal input user_address_hash;
    signal input anchor_public_key[2];
    signal input current_time;              // Current timestamp for validation
    
    // Private inputs
    signal input user_address;
    signal input timestamp;
    signal input signature_r[2];
    signal input signature_s;
    
    // Output
    signal output valid;
    
    // Components
    component deposit_proof = DepositProof();
    component timestamp_validator = TimestampValidator(3600); // 1 hour max age
    
    // Connect deposit proof inputs
    deposit_proof.amount <== amount;
    deposit_proof.user_address_hash <== user_address_hash;
    deposit_proof.anchor_public_key[0] <== anchor_public_key[0];
    deposit_proof.anchor_public_key[1] <== anchor_public_key[1];
    deposit_proof.user_address <== user_address;
    deposit_proof.timestamp <== timestamp;
    deposit_proof.signature_r[0] <== signature_r[0];
    deposit_proof.signature_r[1] <== signature_r[1];
    deposit_proof.signature_s <== signature_s;
    
    // Validate timestamp
    timestamp_validator.timestamp <== timestamp;
    timestamp_validator.current_time <== current_time;
    
    // Both proofs must be valid
    valid <== deposit_proof.valid * timestamp_validator.valid;
}

/*
 * Batch Deposit Proof
 * Allows proving multiple deposits in a single proof for efficiency
 */
template BatchDepositProof(n) {
    // Public inputs (arrays of size n)
    signal input amounts[n];
    signal input user_address_hashes[n];
    signal input anchor_public_key[2];      // Same anchor for all deposits
    
    // Private inputs (arrays of size n)
    signal input user_addresses[n];
    signal input timestamps[n];
    signal input signature_r[n][2];
    signal input signature_s[n];
    
    // Output
    signal output valid;
    signal output total_amount;             // Sum of all amounts
    
    // Components
    component deposit_proofs[n];
    
    // Initialize total
    var running_total = 0;
    
    // Verify each deposit
    for (var i = 0; i < n; i++) {
        deposit_proofs[i] = DepositProof();
        
        deposit_proofs[i].amount <== amounts[i];
        deposit_proofs[i].user_address_hash <== user_address_hashes[i];
        deposit_proofs[i].anchor_public_key[0] <== anchor_public_key[0];
        deposit_proofs[i].anchor_public_key[1] <== anchor_public_key[1];
        deposit_proofs[i].user_address <== user_addresses[i];
        deposit_proofs[i].timestamp <== timestamps[i];
        deposit_proofs[i].signature_r[0] <== signature_r[i][0];
        deposit_proofs[i].signature_r[1] <== signature_r[i][1];
        deposit_proofs[i].signature_s <== signature_s[i];
        
        running_total += amounts[i];
    }
    
    // Calculate total amount
    total_amount <== running_total;
    
    // All proofs must be valid
    var all_valid = 1;
    for (var i = 0; i < n; i++) {
        all_valid *= deposit_proofs[i].valid;
    }
    valid <== all_valid;
}

// Main component - choose which version to use
component main = DepositProofWithTimestamp();