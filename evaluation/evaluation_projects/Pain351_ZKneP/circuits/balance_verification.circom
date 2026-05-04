pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom";

template BalanceVerification() {
    // Private inputs
    signal input actualBalance;
    signal input availableBalance;
    signal input dailySpent;
    
    // Public inputs
    signal input minBalance;
    signal input requestedAmount;
    signal input dailyLimit;
    signal input accountType;
    
    // Public outputs
    signal output hasMinBalance;
    signal output canSpendAmount;
    signal output accountStatus;
    
    // Check minimum balance
    component minBalanceCheck = GreaterEqThan(64);
    minBalanceCheck.in[0] <== actualBalance;
    minBalanceCheck.in[1] <== minBalance;
    hasMinBalance <== minBalanceCheck.out;
    
    // Check spending capability
    component spendCheck = GreaterEqThan(64);
    spendCheck.in[0] <== availableBalance;
    spendCheck.in[1] <== requestedAmount;
    
    // Check daily limit
    signal remainingDaily <== dailyLimit - dailySpent;
    component dailyCheck = GreaterEqThan(64);
    dailyCheck.in[0] <== remainingDaily;
    dailyCheck.in[1] <== requestedAmount;
    
    // FIXED: Proper signal assignments
    canSpendAmount <== spendCheck.out * dailyCheck.out;
    accountStatus <== hasMinBalance * canSpendAmount;
}

component main = BalanceVerification();