pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom";

template ClientBalanceComparison() {
    // Private inputs
    signal input balanceA;
    signal input balanceB;
    
    // Public inputs
    signal input threshold;
    signal input operation; // 0=both above, 1=sum above, 2=difference within range
    
    // Public outputs
    signal output comparisonResult;
    
    // Operation 0: Both balances above threshold
    component checkA = GreaterEqThan(64);
    checkA.in[0] <== balanceA;
    checkA.in[1] <== threshold;
    
    component checkB = GreaterEqThan(64);
    checkB.in[0] <== balanceB;
    checkB.in[1] <== threshold;
    
    signal bothAbove <== checkA.out * checkB.out;
    
    // Operation 1: Sum above threshold
    component sumCheck = GreaterEqThan(64);
    sumCheck.in[0] <== balanceA + balanceB;
    sumCheck.in[1] <== threshold;
    
    // Operation 2: Difference within range
    signal diff <== balanceA - balanceB;
    component isNegative = LessThan(64);
    isNegative.in[0] <== diff;
    isNegative.in[1] <== 0;
    
    // Get absolute difference
    signal negDiff <== isNegative.out * (-diff);
    signal posDiff <== (1 - isNegative.out) * diff;
    signal absDiff <== negDiff + posDiff;
    
    component diffCheck = LessEqThan(64);
    diffCheck.in[0] <== absDiff;
    diffCheck.in[1] <== threshold;
    
    // Operation selection
    component op0 = IsEqual();
    op0.in[0] <== operation;
    op0.in[1] <== 0;
    
    component op1 = IsEqual();
    op1.in[0] <== operation;
    op1.in[1] <== 1;
    
    component op2 = IsEqual();
    op2.in[0] <== operation;
    op2.in[1] <== 2;
    
    // FIXED: Calculate result step by step
    signal result0 <== op0.out * bothAbove;
    signal result1 <== op1.out * sumCheck.out;
    signal result2 <== op2.out * diffCheck.out;
    
    comparisonResult <== result0 + result1 + result2;
}

component main = ClientBalanceComparison();