pragma circom 2.0.0;

template CreditScoreProof() {
    // Private inputs (hidden from verifier)
    signal private input credit_score;
    signal private input account_age;
    signal private input payment_history;
    signal private input credit_utilization;
    signal private input debt_to_income;
    signal private input privacy_level;
    signal private input nullifier_secret;
    
    // Public inputs (visible to verifier)
    signal input score_threshold;
    signal input transparency_mask;
    signal input nullifier_hash;
    
    // Outputs
    signal output score_in_range;
    signal output masked_score;
    signal output privacy_premium;
    
    // Simple constraint: Credit score must meet the threshold
    component gte_score = LessThan(10);
    gte_score.in[0] <== score_threshold - 1;
    gte_score.in[1] <== credit_score;
    
    // Score must be in valid range (300-850)
    component valid_min = LessThan(10);
    valid_min.in[0] <== 299;
    valid_min.in[1] <== credit_score;
    
    component valid_max = LessThan(10);
    valid_max.in[0] <== credit_score;
    valid_max.in[1] <== 851;
    
    // Calculate score range validation
    score_in_range <== gte_score.out * valid_min.out * valid_max.out;
    
    // Calculate masked score based on privacy level
    signal privacy_multiplier;
    privacy_multiplier <== (6 - privacy_level) * 20; // 20, 40, 60, 80, 100
    
    masked_score <== credit_score * transparency_mask * privacy_multiplier / 100;
    
    // Calculate privacy premium (higher privacy = lower premium)
    // Level 5: 0% premium, Level 1: 2% premium
    privacy_premium <== (6 - privacy_level) * 50; // 50, 100, 150, 200, 250 (basis points)
    
    // Simple nullifier hash constraint (for demo)
    nullifier_hash === nullifier_secret + credit_score;
}

// Basic LessThan template for our constraints
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component lt = Num2Bits(n + 1);
    lt.in <== in[0] + (1 << n) - in[1];

    out <== 1 - lt.out[n];
}

// Simple Num2Bits template
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

component main = CreditScoreProof(); 