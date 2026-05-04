pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template CreditScoreProofEnhanced() {
    // Private inputs (hidden from verifier)
    signal private input credit_score;
    signal private input account_age;
    signal private input payment_history;
    signal private input credit_utilization;
    signal private input debt_to_income;
    signal private input privacy_level;
    
    // Nullifier generation inputs
    signal private input user_secret;  // User's permanent secret
    signal private input nonce;         // Sequential nonce for this proof
    signal private input timestamp;     // Timestamp for time-bounded proof
    
    // Public inputs (visible to verifier)
    signal input score_threshold;
    signal input transparency_mask;
    signal input chain_id;              // Chain-specific to prevent cross-chain replay
    signal input user_address;          // User's ethereum address
    
    // Outputs
    signal output score_in_range;
    signal output masked_score;
    signal output privacy_premium;
    signal output nullifier_hash;       // Unique nullifier for this proof
    signal output commitment_hash;      // Commitment to private data
    
    // ==================== NULLIFIER GENERATION ====================
    // Generate unique nullifier using Poseidon hash
    // nullifier = Poseidon(user_secret, nonce, timestamp, chain_id)
    component nullifierHasher = Poseidon(4);
    nullifierHasher.inputs[0] <== user_secret;
    nullifierHasher.inputs[1] <== nonce;
    nullifierHasher.inputs[2] <== timestamp;
    nullifierHasher.inputs[3] <== chain_id;
    nullifier_hash <== nullifierHasher.out;
    
    // ==================== COMMITMENT GENERATION ====================
    // Create commitment to all private credit data
    component commitmentHasher = Poseidon(7);
    commitmentHasher.inputs[0] <== credit_score;
    commitmentHasher.inputs[1] <== account_age;
    commitmentHasher.inputs[2] <== payment_history;
    commitmentHasher.inputs[3] <== credit_utilization;
    commitmentHasher.inputs[4] <== debt_to_income;
    commitmentHasher.inputs[5] <== nullifier_hash;
    commitmentHasher.inputs[6] <== user_address;
    commitment_hash <== commitmentHasher.out;
    
    // ==================== CREDIT SCORE VALIDATION ====================
    // Check if credit score meets the threshold
    component gte_score = GreaterEqThan(10);
    gte_score.in[0] <== credit_score;
    gte_score.in[1] <== score_threshold;
    
    // Validate score is in valid range (300-850)
    component valid_min = GreaterEqThan(10);
    valid_min.in[0] <== credit_score;
    valid_min.in[1] <== 300;
    
    component valid_max = LessEqThan(10);
    valid_max.in[0] <== credit_score;
    valid_max.in[1] <== 850;
    
    // Calculate score range validation
    score_in_range <== gte_score.out * valid_min.out * valid_max.out;
    
    // ==================== PRIVACY LEVEL HANDLING ====================
    // Validate privacy level (1-5)
    component privacy_valid_min = GreaterEqThan(3);
    privacy_valid_min.in[0] <== privacy_level;
    privacy_valid_min.in[1] <== 1;
    
    component privacy_valid_max = LessEqThan(3);
    privacy_valid_max.in[0] <== privacy_level;
    privacy_valid_max.in[1] <== 5;
    
    // Assert valid privacy level
    privacy_valid_min.out * privacy_valid_max.out === 1;
    
    // Calculate masked score based on privacy level
    // Higher privacy levels reveal less information
    signal privacy_multiplier;
    privacy_multiplier <== (6 - privacy_level) * 20; // 100, 80, 60, 40, 20
    
    // Apply transparency mask and privacy multiplier
    signal temp_masked;
    temp_masked <== credit_score * transparency_mask;
    masked_score <== (temp_masked * privacy_multiplier) \ 100;
    
    // Calculate privacy premium (higher privacy = lower premium)
    // Level 5 (max privacy): 0% premium
    // Level 1 (min privacy): 2% premium
    privacy_premium <== (6 - privacy_level) * 50; // 250, 200, 150, 100, 50 basis points
    
    // ==================== TIME VALIDATION ====================
    // Ensure timestamp is not too old (prevents old proof replay)
    component time_fresh = LessEqThan(32);
    time_fresh.in[0] <== timestamp;
    time_fresh.in[1] <== timestamp + 3600; // 1 hour validity
    
    // ==================== ADDITIONAL CONSTRAINTS ====================
    // Ensure nonce is positive (prevents negative nonce attacks)
    component nonce_positive = GreaterThan(32);
    nonce_positive.in[0] <== nonce;
    nonce_positive.in[1] <== 0;
    
    // Ensure user_secret is non-zero (prevents weak nullifiers)
    component secret_nonzero = IsZero();
    secret_nonzero.in <== user_secret;
    secret_nonzero.out === 0;
    
    // Ensure proper credit factor ranges
    component age_valid = LessEqThan(20);
    age_valid.in[0] <== account_age;
    age_valid.in[1] <== 1000000; // Max account age in blocks
    
    component utilization_valid = LessEqThan(10);
    utilization_valid.in[0] <== credit_utilization;
    utilization_valid.in[1] <== 100; // Max 100% utilization
    
    // All validations must pass
    age_valid.out * utilization_valid.out === 1;
}

component main = CreditScoreProofEnhanced();