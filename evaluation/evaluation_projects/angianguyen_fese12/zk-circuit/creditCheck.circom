include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/gates.circom";

// Helper template: GreaterEqThan (a >= b)
// Returns 1 if in[0] >= in[1], else 0
template GreaterEqThan(n) {
    signal input in[2];
    signal output out;
    
    // a >= b is equivalent to NOT(a < b)
    component lt = LessThan(n);
    lt.in[0] <== in[0];
    lt.in[1] <== in[1];
    
    out <== 1 - lt.out;
}

// Credit Check Circuit with Benford's Law fraud detection
// Process 100 orders and verify revenue + fraud score
template CreditCheck() {
    // Private inputs (not revealed)
    signal private input orderAmounts[100];  // Array of 100 order amounts
    signal private input benfordScore;       // Benford score calculated off-chain
    
    // Public inputs
    signal input revenueThreshold;  // Minimum revenue threshold (e.g., 500000)
    signal input benfordThreshold;  // Fraud detection threshold (e.g., 20)
    
    // Output
    signal output isValid;  // 1 = Pass, 0 = Fail
    
    // Intermediate signals
    signal totalRevenue;
    signal revenueCheck;
    signal benfordCheck;
    
    // 1. Calculate total revenue from orders
    var i;
    var sum;
    sum = 0;
    for (i = 0; i < 100; i++) {
        sum = sum + orderAmounts[i];
    }
    totalRevenue <-- sum;
    totalRevenue === sum;
    
    // 2. Check revenue >= threshold
    component revenueGate = GreaterEqThan(64);
    revenueGate.in[0] <== totalRevenue;
    revenueGate.in[1] <== revenueThreshold;
    revenueCheck <== revenueGate.out;
    
    // 3. Benford's Law check
    // Seller calculates benfordScore off-chain from orderAmounts
    // Circuit only verifies it's below threshold
    component benfordGate = LessThan(64);
    benfordGate.in[0] <== benfordScore;
    benfordGate.in[1] <== benfordThreshold;
    benfordCheck <== benfordGate.out;
    
    // 4. Both conditions must be true
    component andGate = AND();
    andGate.a <== revenueCheck;
    andGate.b <== benfordCheck;
    isValid <== andGate.out;
}

// Main component
component main = CreditCheck();
