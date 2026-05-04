pragma circom 2.0.0;

/**
 * Multi-Chain Credit Score ZK Circuit
 * Proves credit eligibility across multiple chains while preserving privacy
 * Supports universal credit scores with chain-specific weights and bonuses
 */

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/mimc.circom";
include "circomlib/circuits/poseidon.circom";

/**
 * Component to verify credit score from a single chain
 */
template ChainCreditVerification() {
    // Private inputs for each chain
    signal private input chain_score;           // Credit score on this chain
    signal private input chain_weight;          // Weight of this chain (basis points)
    signal private input transaction_volume;    // Total transaction volume
    signal private input account_age;          // Account age on this chain
    signal private input defi_participation;   // DeFi participation score
    signal private input repayment_history;    // Repayment history score
    
    // Public parameters
    signal input min_score_threshold;          // Minimum score required
    signal input chain_id;                     // Chain identifier
    
    // Outputs
    signal output weighted_score;              // Chain score * weight
    signal output is_eligible;                 // 1 if meets threshold, 0 otherwise
    signal output activity_bonus;              // Bonus points for this chain
    
    // Verify score is in valid range (300-850)
    component score_min_check = GreaterEqualThan(16);
    score_min_check.in[0] <== chain_score;
    score_min_check.in[1] <== 300;
    
    component score_max_check = LessEqualThan(16);
    score_max_check.in[0] <== chain_score;
    score_max_check.in[1] <== 850;
    
    component score_valid = AND();
    score_valid.a <== score_min_check.out;
    score_valid.b <== score_max_check.out;
    
    // Calculate weighted score
    weighted_score <== chain_score * chain_weight;
    
    // Check if score meets threshold
    component threshold_check = GreaterEqualThan(16);
    threshold_check.in[0] <== chain_score;
    threshold_check.in[1] <== min_score_threshold;
    
    is_eligible <== threshold_check.out * score_valid.out;
    
    // Calculate activity bonus based on various factors
    component volume_bonus = VolumeBonus();
    volume_bonus.transaction_volume <== transaction_volume;
    volume_bonus.account_age <== account_age;
    
    component defi_bonus = DeFiBonus();
    defi_bonus.defi_participation <== defi_participation;
    
    component history_bonus = HistoryBonus();
    history_bonus.repayment_history <== repayment_history;
    
    activity_bonus <== volume_bonus.bonus + defi_bonus.bonus + history_bonus.bonus;
}

/**
 * Component to calculate volume-based bonus
 */
template VolumeBonus() {
    signal input transaction_volume;
    signal input account_age;
    signal output bonus;
    
    // High volume bonus (simplified logic)
    component high_volume = GreaterThan(32);
    high_volume.in[0] <== transaction_volume;
    high_volume.in[1] <== 1000000; // 1M wei threshold
    
    // Account maturity bonus
    component mature_account = GreaterThan(32);
    mature_account.in[0] <== account_age;
    mature_account.in[1] <== 365 * 24 * 3600; // 1 year in seconds
    
    bonus <== high_volume.out * 10 + mature_account.out * 5;
}

/**
 * Component to calculate DeFi participation bonus
 */
template DeFiBonus() {
    signal input defi_participation;
    signal output bonus;
    
    // High DeFi participation bonus
    component high_defi = GreaterThan(16);
    high_defi.in[0] <== defi_participation;
    high_defi.in[1] <== 700; // High DeFi score threshold
    
    component medium_defi = GreaterThan(16);
    medium_defi.in[0] <== defi_participation;
    medium_defi.in[1] <== 500; // Medium DeFi score threshold
    
    // Tiered bonus system
    bonus <== high_defi.out * 15 + medium_defi.out * 8;
}

/**
 * Component to calculate repayment history bonus
 */
template HistoryBonus() {
    signal input repayment_history;
    signal output bonus;
    
    // Excellent repayment history bonus
    component excellent_history = GreaterThan(16);
    excellent_history.in[0] <== repayment_history;
    excellent_history.in[1] <== 800;
    
    component good_history = GreaterThan(16);
    good_history.in[0] <== repayment_history;
    good_history.in[1] <== 600;
    
    bonus <== excellent_history.out * 20 + good_history.out * 10;
}

/**
 * Component to calculate cross-chain bonuses
 */
template CrossChainBonus() {
    signal input num_active_chains;           // Number of chains with activity
    signal input score_consistency;          // Measure of score consistency across chains
    signal input total_volume;              // Aggregate volume across all chains
    signal input defi_sophistication;       // Advanced DeFi usage across chains
    
    signal output diversification_bonus;
    signal output consistency_bonus;
    signal output volume_bonus;
    signal output sophistication_bonus;
    
    // Diversification bonus (more chains = higher bonus)
    component five_plus_chains = GreaterEqualThan(8);
    five_plus_chains.in[0] <== num_active_chains;
    five_plus_chains.in[1] <== 5;
    
    component three_plus_chains = GreaterEqualThan(8);
    three_plus_chains.in[0] <== num_active_chains;
    three_plus_chains.in[1] <== 3;
    
    component two_plus_chains = GreaterEqualThan(8);
    two_plus_chains.in[0] <== num_active_chains;
    two_plus_chains.in[1] <== 2;
    
    diversification_bonus <== five_plus_chains.out * 65 + 
                             three_plus_chains.out * 40 + 
                             two_plus_chains.out * 25;
    
    // Consistency bonus (similar scores across chains)
    component very_consistent = GreaterThan(16);
    very_consistent.in[0] <== score_consistency;
    very_consistent.in[1] <== 800; // High consistency score
    
    component consistent = GreaterThan(16);
    consistent.in[0] <== score_consistency;
    consistent.in[1] <== 600; // Medium consistency score
    
    consistency_bonus <== very_consistent.out * 30 + consistent.out * 20;
    
    // Volume bonus (high aggregate activity)
    component high_total_volume = GreaterThan(64);
    high_total_volume.in[0] <== total_volume;
    high_total_volume.in[1] <== 10000000; // 10M wei threshold
    
    component medium_total_volume = GreaterThan(64);
    medium_total_volume.in[0] <== total_volume;
    medium_total_volume.in[1] <== 1000000; // 1M wei threshold
    
    volume_bonus <== high_total_volume.out * 25 + medium_total_volume.out * 15;
    
    // Sophistication bonus (advanced multi-chain DeFi usage)
    component advanced_defi = GreaterThan(16);
    advanced_defi.in[0] <== defi_sophistication;
    advanced_defi.in[1] <== 750;
    
    component intermediate_defi = GreaterThan(16);
    intermediate_defi.in[0] <== defi_sophistication;
    intermediate_defi.in[1] <== 500;
    
    sophistication_bonus <== advanced_defi.out * 20 + intermediate_defi.out * 10;
}

/**
 * Main multi-chain credit score verification circuit
 */
template MultiChainCreditScore(num_chains) {
    // Private inputs (hidden from verifier)
    signal private input chain_scores[num_chains];           // Credit scores on each chain
    signal private input chain_weights[num_chains];          // Weights for each chain
    signal private input transaction_volumes[num_chains];    // Transaction volumes per chain
    signal private input account_ages[num_chains];          // Account ages per chain
    signal private input defi_participations[num_chains];   // DeFi participation per chain
    signal private input repayment_histories[num_chains];   // Repayment histories per chain
    signal private input active_chains[num_chains];         // 1 if chain is active, 0 otherwise
    signal private input privacy_level;                     // Privacy level (1-5)
    signal private input nullifier_secret;                  // Secret for nullifier generation
    
    // Public inputs
    signal input min_score_threshold;                       // Minimum required score
    signal input loan_amount;                              // Requested loan amount
    signal input chain_ids[num_chains];                    // Chain identifiers
    
    // Public outputs (verifiable without revealing private data)
    signal output score_in_range;                          // 1 if universal score meets threshold
    signal output masked_score;                            // Privacy-adjusted score reveal
    signal output privacy_premium;                         // Cost adjustment for privacy level
    signal output nullifier_hash;                          // Prevents double-spending
    signal output num_active_chains;                       // Number of chains with activity
    signal output total_weighted_score;                    // Total weighted score (for verification)
    
    // Components for each chain verification
    component chain_verifiers[num_chains];
    var total_weighted = 0;
    var total_weight = 0;
    var active_count = 0;
    var total_volume = 0;
    var avg_defi_participation = 0;
    
    // Verify each chain's credit data
    for (var i = 0; i < num_chains; i++) {
        chain_verifiers[i] = ChainCreditVerification();
        chain_verifiers[i].chain_score <== chain_scores[i];
        chain_verifiers[i].chain_weight <== chain_weights[i];
        chain_verifiers[i].transaction_volume <== transaction_volumes[i];
        chain_verifiers[i].account_age <== account_ages[i];
        chain_verifiers[i].defi_participation <== defi_participations[i];
        chain_verifiers[i].repayment_history <== repayment_histories[i];
        chain_verifiers[i].min_score_threshold <== min_score_threshold;
        chain_verifiers[i].chain_id <== chain_ids[i];
        
        // Accumulate weighted scores and other metrics
        total_weighted += chain_verifiers[i].weighted_score * active_chains[i];
        total_weight += chain_weights[i] * active_chains[i];
        active_count += active_chains[i];
        total_volume += transaction_volumes[i] * active_chains[i];
        avg_defi_participation += defi_participations[i] * active_chains[i];
    }
    
    // Calculate universal score
    component weight_check = GreaterThan(32);
    weight_check.in[0] <== total_weight;
    weight_check.in[1] <== 0;
    
    var base_universal_score = total_weight > 0 ? total_weighted / total_weight : 0;
    
    // Calculate cross-chain bonuses
    component cross_chain_bonus = CrossChainBonus();
    cross_chain_bonus.num_active_chains <== active_count;
    cross_chain_bonus.score_consistency <== 750; // Simplified - would calculate variance
    cross_chain_bonus.total_volume <== total_volume;
    cross_chain_bonus.defi_sophistication <== active_count > 0 ? avg_defi_participation / active_count : 0;
    
    var total_bonus = cross_chain_bonus.diversification_bonus + 
                     cross_chain_bonus.consistency_bonus + 
                     cross_chain_bonus.volume_bonus + 
                     cross_chain_bonus.sophistication_bonus;
    
    var final_universal_score = base_universal_score + total_bonus;
    
    // Cap at maximum score (850)
    component max_score_check = LessEqualThan(16);
    max_score_check.in[0] <== final_universal_score;
    max_score_check.in[1] <== 850;
    
    var capped_score = max_score_check.out * final_universal_score + (1 - max_score_check.out) * 850;
    
    // Check if score meets threshold
    component threshold_met = GreaterEqualThan(16);
    threshold_met.in[0] <== capped_score;
    threshold_met.in[1] <== min_score_threshold;
    
    score_in_range <== threshold_met.out;
    
    // Apply privacy masking based on privacy level
    component privacy_mask = PrivacyMask();
    privacy_mask.actual_score <== capped_score;
    privacy_mask.privacy_level <== privacy_level;
    privacy_mask.loan_amount <== loan_amount;
    
    masked_score <== privacy_mask.masked_score;
    privacy_premium <== privacy_mask.premium;
    
    // Generate nullifier to prevent double-spending
    component nullifier_hasher = Poseidon(3);
    nullifier_hasher.inputs[0] <== nullifier_secret;
    nullifier_hasher.inputs[1] <== capped_score;
    nullifier_hasher.inputs[2] <== loan_amount;
    
    nullifier_hash <== nullifier_hasher.out;
    
    // Output metrics
    num_active_chains <== active_count;
    total_weighted_score <== total_weighted;
}

/**
 * Component to handle privacy masking and premium calculation
 */
template PrivacyMask() {
    signal input actual_score;
    signal input privacy_level;     // 1-5, where 5 is maximum privacy
    signal input loan_amount;
    
    signal output masked_score;
    signal output premium;          // Interest rate premium for privacy (basis points)
    
    // Privacy level 5: Maximum privacy (score completely hidden, no premium)
    component level_5 = IsEqual();
    level_5.in[0] <== privacy_level;
    level_5.in[1] <== 5;
    
    // Privacy level 4: High privacy (basic eligibility only, 0.5% premium)
    component level_4 = IsEqual();
    level_4.in[0] <== privacy_level;
    level_4.in[1] <== 4;
    
    // Privacy level 3: Medium privacy (score range, 1% premium)
    component level_3 = IsEqual();
    level_3.in[0] <== privacy_level;
    level_3.in[1] <== 3;
    
    // Privacy level 2: Low privacy (most factors visible, 1.5% premium)
    component level_2 = IsEqual();
    level_2.in[0] <== privacy_level;
    level_2.in[1] <== 2;
    
    // Privacy level 1: Public (full transparency, 2% premium)
    component level_1 = IsEqual();
    level_1.in[0] <== privacy_level;
    level_1.in[1] <== 1;
    
    // Calculate masked score based on privacy level
    var score_range_low = (actual_score / 100) * 100;  // Round to nearest 100
    var score_range_mid = (actual_score / 50) * 50;    // Round to nearest 50
    
    masked_score <== level_5.out * 0 +                 // Hidden
                    level_4.out * 1 +                  // Just eligibility (1 = eligible)
                    level_3.out * score_range_low +    // Score range (±50)
                    level_2.out * score_range_mid +    // Closer range (±25)
                    level_1.out * actual_score;        // Full score
    
    // Calculate premium (privacy is free at level 5, costs increase for transparency)
    premium <== level_5.out * 0 +      // 0% premium (privacy is free!)
               level_4.out * 50 +       // 0.5% premium
               level_3.out * 100 +      // 1% premium  
               level_2.out * 150 +      // 1.5% premium
               level_1.out * 200;       // 2% premium
}

/**
 * Main component with standard 5 chains (Ethereum, Arbitrum, Polygon, Optimism, Base)
 */
component main = MultiChainCreditScore(5);