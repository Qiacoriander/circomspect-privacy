pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/**
 * VeriChain Financial Status Circuit
 * 
 * This circuit allows a user to prove they have assets above a threshold
 * without revealing their exact balance.
 * 
 * Public Inputs:
 * - minBalance: Minimum required balance (in wei)
 * - commitment: Hash of (actualBalance, assetType, secret)
 * 
 * Private Inputs:
 * - actualBalance: User's actual balance
 * - assetType: Type of asset (1=QIE, 2=BTC, 3=ETH, etc.)
 * - secret: User's secret for commitment
 */
template FinancialStatus() {
    // Public inputs
    signal input minBalance;
    signal input commitment;
    
    // Private inputs
    signal input actualBalance;
    signal input assetType;
    signal input secret;
    
    // Output
    signal output meetsThreshold;
    
    // Verify commitment
    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== actualBalance;
    poseidon.inputs[1] <== assetType;
    poseidon.inputs[2] <== secret;
    commitment === poseidon.out;
    
    // Check actualBalance >= minBalance
    component gte = GreaterEqThan(128); // 128 bits for large balances
    gte.in[0] <== actualBalance;
    gte.in[1] <== minBalance;
    
    meetsThreshold <== gte.out;
    
    // Ensure threshold is met
    meetsThreshold === 1;
}

component main {public [minBalance, commitment]} = FinancialStatus();
