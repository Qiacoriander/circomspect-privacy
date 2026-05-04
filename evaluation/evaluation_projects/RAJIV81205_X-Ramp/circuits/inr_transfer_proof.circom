pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * INR Transfer Proof Circuit
 * 
 * This circuit proves that a user has made a valid INR payment
 * and should receive equivalent XLM without revealing sensitive payment details.
 * 
 * Public Inputs:
 * - inr_amount: The INR amount sent (public for verification)
 * - xlm_amount: The equivalent XLM amount to receive (public)
 * - exchange_rate: INR to XLM exchange rate (public)
 * - recipient_address_hash: Hash of recipient's address (public)
 * - current_time: Current timestamp (public for replay protection)
 * 
 * Private Inputs:
 * - sender_bank_account: Sender's bank account details (private)
 * - transaction_id: Bank transaction ID (private)
 * - recipient_address: Actual recipient address (private)
 * - nonce: Random nonce for uniqueness (private)
 * - payment_signature: Digital signature from bank (private)
 */

template INRTransferProof() {
    // Public inputs
    signal input inr_amount;                // INR amount sent (public)
    signal input xlm_amount;                // XLM amount to receive (public)
    signal input exchange_rate;             // INR to XLM rate (public)
    signal input recipient_address_hash;    // Hash of recipient address (public)
    signal input current_time;              // Current timestamp (public)
    
    // Private inputs
    signal input sender_bank_account;       // Sender's bank account (private)
    signal input transaction_id;            // Bank transaction ID (private)
    signal input recipient_address;         // Recipient's address (private)
    signal input nonce;                     // Random nonce (private)
    signal input payment_signature;         // Bank payment signature (private)
    
    // Output signals
    signal output valid;                    // 1 if proof is valid, 0 otherwise
    
    // Internal components
    component poseidon_recipient = Poseidon(1);
    component poseidon_payment = Poseidon(4);
    component amount_check = GreaterThan(64);
    component exchange_check = GreaterThan(64);
    component time_check = LessThan(64);
    component conversion_check = IsEqual();
    
    // 1. Verify that the recipient_address hashes to recipient_address_hash
    poseidon_recipient.inputs[0] <== recipient_address;
    recipient_address_hash === poseidon_recipient.out;
    
    // 2. Verify that INR amount > 0
    amount_check.in[0] <== inr_amount;
    amount_check.in[1] <== 0;
    
    // 3. Verify that exchange rate > 0
    exchange_check.in[0] <== exchange_rate;
    exchange_check.in[1] <== 0;
    
    // 4. Verify timestamp is reasonable (not too far in future)
    time_check.in[0] <== current_time;
    time_check.in[1] <== 1893456000; // Year 2030 as max reasonable time
    
    // 5. Verify currency conversion is correct
    // xlm_amount should equal (inr_amount * exchange_rate) / 10000
    // We multiply by 10000 to handle decimal precision
    conversion_check.in[0] <== xlm_amount * 10000;
    conversion_check.in[1] <== inr_amount * exchange_rate;
    
    // 6. Create payment hash for signature verification
    // Hash = Poseidon(sender_bank_account, transaction_id, inr_amount, nonce)
    poseidon_payment.inputs[0] <== sender_bank_account;
    poseidon_payment.inputs[1] <== transaction_id;
    poseidon_payment.inputs[2] <== inr_amount;
    poseidon_payment.inputs[3] <== nonce;
    
    // 7. Verify payment signature (simplified - in production use proper signature verification)
    // For now, we just check that signature is non-zero
    component sig_check = GreaterThan(64);
    sig_check.in[0] <== payment_signature;
    sig_check.in[1] <== 0;
    
    // 8. All conditions must be true
    valid <== amount_check.out * exchange_check.out * time_check.out * conversion_check.out * sig_check.out;
}

/*
 * Batch INR Transfer Proof
 * Allows proving multiple INR transfers in a single proof
 */
template BatchINRTransferProof(n) {
    // Public inputs (arrays)
    signal input inr_amounts[n];
    signal input xlm_amounts[n];
    signal input exchange_rates[n];
    signal input recipient_address_hashes[n];
    signal input current_time;
    
    // Private inputs (arrays)
    signal input sender_bank_accounts[n];
    signal input transaction_ids[n];
    signal input recipient_addresses[n];
    signal input nonces[n];
    signal input payment_signatures[n];
    
    // Output
    signal output valid;
    signal output total_inr;
    signal output total_xlm;
    
    // Components for each transfer
    component transfers[n];
    component inr_sum = Sum(n);
    component xlm_sum = Sum(n);
    
    // Verify each transfer and sum amounts
    for (var i = 0; i < n; i++) {
        transfers[i] = INRTransferProof();
        
        transfers[i].inr_amount <== inr_amounts[i];
        transfers[i].xlm_amount <== xlm_amounts[i];
        transfers[i].exchange_rate <== exchange_rates[i];
        transfers[i].recipient_address_hash <== recipient_address_hashes[i];
        transfers[i].current_time <== current_time;
        
        transfers[i].sender_bank_account <== sender_bank_accounts[i];
        transfers[i].transaction_id <== transaction_ids[i];
        transfers[i].recipient_address <== recipient_addresses[i];
        transfers[i].nonce <== nonces[i];
        transfers[i].payment_signature <== payment_signatures[i];
        
        inr_sum.inputs[i] <== inr_amounts[i];
        xlm_sum.inputs[i] <== xlm_amounts[i];
    }
    
    total_inr <== inr_sum.out;
    total_xlm <== xlm_sum.out;
    
    // All transfers must be valid
    component and_gate = MultiAND(n);
    for (var i = 0; i < n; i++) {
        and_gate.in[i] <== transfers[i].valid;
    }
    
    valid <== and_gate.out;
}

// Helper template for summing arrays
template Sum(n) {
    signal input inputs[n];
    signal output out;
    
    if (n == 1) {
        out <== inputs[0];
    } else {
        component sum_rest = Sum(n-1);
        for (var i = 0; i < n-1; i++) {
            sum_rest.inputs[i] <== inputs[i+1];
        }
        out <== inputs[0] + sum_rest.out;
    }
}

// Helper template for multiple AND operations
template MultiAND(n) {
    signal input in[n];
    signal output out;
    
    if (n == 1) {
        out <== in[0];
    } else if (n == 2) {
        component and2 = AND();
        and2.a <== in[0];
        and2.b <== in[1];
        out <== and2.out;
    } else {
        component and2 = AND();
        component rest = MultiAND(n-1);
        
        and2.a <== in[0];
        for (var i = 0; i < n-1; i++) {
            rest.in[i] <== in[i+1];
        }
        and2.b <== rest.out;
        out <== and2.out;
    }
}

// Main component
component main = INRTransferProof();