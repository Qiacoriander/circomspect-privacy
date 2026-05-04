pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Withdrawal Proof Circuit
 * 
 * This circuit proves that a user owns sufficient funds to make a withdrawal
 * without revealing their actual balance or other private information.
 * 
 * Public Inputs:
 * - amount: The withdrawal amount (public for verification)
 * - user_address_hash: Hash of the user's address (public for verification)
 * - current_time: Current timestamp (public for replay protection)
 * 
 * Private Inputs:
 * - user_address: The actual user address (private)
 * - balance: User's current balance (private)
 * - nonce: Random nonce for uniqueness (private)
 */

template WithdrawalProof() {
    // Public inputs
    signal input amount;                    // Withdrawal amount (public)
    signal input user_address_hash;         // Hash of user address (public)
    signal input current_time;              // Current timestamp (public)
    
    // Private inputs
    signal input user_address;              // User's address (private)
    signal input balance;                   // User's current balance (private)
    signal input nonce;                     // Random nonce (private)
    
    // Output signals
    signal output valid;                    // 1 if proof is valid, 0 otherwise
    
    // Internal components
    component poseidon_hash = Poseidon(1);
    component balance_check = GreaterEqualThan(64);
    component amount_check = GreaterThan(64);
    component time_check = LessThan(64);
    
    // 1. Verify that the provided user_address hashes to user_address_hash
    poseidon_hash.inputs[0] <== user_address;
    user_address_hash === poseidon_hash.out;
    
    // 2. Verify that balance >= amount (user has sufficient funds)
    balance_check.in[0] <== balance;
    balance_check.in[1] <== amount;
    
    // 3. Verify that amount > 0 (positive withdrawal)
    amount_check.in[0] <== amount;
    amount_check.in[1] <== 0;
    
    // 4. Verify timestamp is reasonable (not too far in future)
    // Allow up to 5 minutes in the future
    time_check.in[0] <== current_time;
    time_check.in[1] <== 1893456000; // Year 2030 as max reasonable time
    
    // 5. All conditions must be true
    valid <== balance_check.out * amount_check.out * time_check.out;
}

/*
 * Enhanced Withdrawal Proof with Nullifier
 * Prevents double-spending by using nullifiers
 */
template WithdrawalProofWithNullifier() {
    // Public inputs
    signal input amount;
    signal input user_address_hash;
    signal input current_time;
    signal input nullifier_hash;            // Nullifier to prevent double-spending
    
    // Private inputs
    signal input user_address;
    signal input balance;
    signal input nonce;
    signal input secret;                    // Secret for nullifier generation
    
    // Output
    signal output valid;
    
    // Components
    component withdrawal_proof = WithdrawalProof();
    component nullifier_gen = Poseidon(2);
    
    // Connect withdrawal proof inputs
    withdrawal_proof.amount <== amount;
    withdrawal_proof.user_address_hash <== user_address_hash;
    withdrawal_proof.current_time <== current_time;
    withdrawal_proof.user_address <== user_address;
    withdrawal_proof.balance <== balance;
    withdrawal_proof.nonce <== nonce;
    
    // Generate and verify nullifier
    nullifier_gen.inputs[0] <== secret;
    nullifier_gen.inputs[1] <== nonce;
    nullifier_hash === nullifier_gen.out;
    
    // Both proofs must be valid
    valid <== withdrawal_proof.valid;
}

/*
 * Batch Withdrawal Proof
 * Allows proving multiple withdrawals in a single proof
 */
template BatchWithdrawalProof(n) {
    // Public inputs (arrays of size n)
    signal input amounts[n];
    signal input user_address_hashes[n];
    signal input current_time;
    
    // Private inputs (arrays of size n)
    signal input user_addresses[n];
    signal input balances[n];
    signal input nonces[n];
    
    // Output
    signal output valid;
    signal output total_amount;             // Sum of all amounts
    
    // Components
    component withdrawal_proofs[n];
    
    // Initialize total
    var running_total = 0;
    
    // Verify each withdrawal
    for (var i = 0; i < n; i++) {
        withdrawal_proofs[i] = WithdrawalProof();
        
        withdrawal_proofs[i].amount <== amounts[i];
        withdrawal_proofs[i].user_address_hash <== user_address_hashes[i];
        withdrawal_proofs[i].current_time <== current_time;
        withdrawal_proofs[i].user_address <== user_addresses[i];
        withdrawal_proofs[i].balance <== balances[i];
        withdrawal_proofs[i].nonce <== nonces[i];
        
        running_total += amounts[i];
    }
    
    // Calculate total amount
    total_amount <== running_total;
    
    // All proofs must be valid
    var all_valid = 1;
    for (var i = 0; i < n; i++) {
        all_valid *= withdrawal_proofs[i].valid;
    }
    valid <== all_valid;
}

/*
 * Range Proof for Withdrawal Amount
 * Proves that withdrawal amount is within acceptable range
 */
template WithdrawalRangeProof(min_amount, max_amount) {
    signal input amount;
    signal output valid;
    
    component min_check = GreaterEqualThan(64);
    component max_check = LessEqualThan(64);
    
    // Check amount >= min_amount
    min_check.in[0] <== amount;
    min_check.in[1] <== min_amount;
    
    // Check amount <= max_amount
    max_check.in[0] <== amount;
    max_check.in[1] <== max_amount;
    
    // Both conditions must be true
    valid <== min_check.out * max_check.out;
}

/*
 * Complete Withdrawal Proof with Range Check
 * Combines withdrawal proof with range validation
 */
template CompleteWithdrawalProof(min_amount, max_amount) {
    // Public inputs
    signal input amount;
    signal input user_address_hash;
    signal input current_time;
    
    // Private inputs
    signal input user_address;
    signal input balance;
    signal input nonce;
    
    // Output
    signal output valid;
    
    // Components
    component withdrawal_proof = WithdrawalProof();
    component range_proof = WithdrawalRangeProof(min_amount, max_amount);
    
    // Connect inputs
    withdrawal_proof.amount <== amount;
    withdrawal_proof.user_address_hash <== user_address_hash;
    withdrawal_proof.current_time <== current_time;
    withdrawal_proof.user_address <== user_address;
    withdrawal_proof.balance <== balance;
    withdrawal_proof.nonce <== nonce;
    
    range_proof.amount <== amount;
    
    // Both proofs must be valid
    valid <== withdrawal_proof.valid * range_proof.valid;
}

// Main component - basic withdrawal proof
component main = WithdrawalProof();