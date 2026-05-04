pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/**
 * Balance Proof Circuit for PrivOTC
 * Proves: user has balance >= required_amount without revealing actual balance
 * Adapted from idAuth.circom pattern in zk-affordability-loan
 */
template BalanceProof() {
    // ===== PRIVATE INPUTS (never revealed) =====
    signal input wallet_address;        // User's wallet address (as felt252)
    signal input actual_balance;        // Actual token balance (private)
    signal input token_address;         // Token contract address (private)
    signal input salt;                  // Random salt for commitment
    signal input balance_proof_data;    // Additional proof data (e.g., block number)
    
    // ===== PUBLIC INPUTS =====
    signal input required_amount;       // Minimum required balance (public)
    signal input timestamp;             // Proof generation timestamp (public)
    
    // ===== PUBLIC OUTPUTS =====
    signal output balance_sufficient;   // 1 if balance >= required, 0 otherwise
    signal output wallet_commitment;    // Hash commitment of wallet (prevents front-running)
    signal output proof_hash;           // Unique proof identifier
    
    // ===== BALANCE VERIFICATION =====
    // Check if actual_balance >= required_amount
    component balance_check = GreaterEqThan(252); // 252-bit comparison (felt252)
    balance_check.in[0] <== actual_balance;
    balance_check.in[1] <== required_amount;
    balance_sufficient <== balance_check.out;
    
    // Constrain: balance must be sufficient (proof fails if balance < required)
    balance_sufficient === 1;
    
    // ===== WALLET COMMITMENT =====
    // Create commitment using Poseidon hash (Starknet-compatible)
    // Prevents wallet address from being revealed publicly
    component wallet_hash = Poseidon(2);
    wallet_hash.inputs[0] <== wallet_address;
    wallet_hash.inputs[1] <== salt;
    wallet_commitment <== wallet_hash.out;
    
    // ===== PROOF HASH =====
    // Generate unique proof identifier to prevent replay attacks
    component proof_hasher = Poseidon(5);
    proof_hasher.inputs[0] <== wallet_commitment;
    proof_hasher.inputs[1] <== token_address;
    proof_hasher.inputs[2] <== required_amount;
    proof_hasher.inputs[3] <== timestamp;
    proof_hasher.inputs[4] <== balance_proof_data;
    proof_hash <== proof_hasher.out;
}

// Public inputs that are visible on-chain (required_amount, timestamp)
// Everything else remains private (wallet_address, actual_balance, token_address, salt, balance_proof_data)
component main {public [required_amount, timestamp]} = BalanceProof();
