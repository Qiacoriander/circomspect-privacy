pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * Confidential Transfer Circuit
 * 
 * Proves that a transfer is valid without revealing amounts:
 * - Input amount equals output amount + fee
 * - All amounts are positive and within valid range
 * - Commitments are correctly formed using Poseidon hash
 * 
 * Public inputs:
 * - inputCommitment: commitment to input amount
 * - outputCommitment: commitment to output amount
 * - fee: transaction fee (revealed)
 * 
 * Private inputs:
 * - inputAmount: actual input amount (secret)
 * - outputAmount: actual output amount (secret)
 * - inputBlinding: input commitment blinding (secret)
 * - outputBlinding: output commitment blinding (secret)
 */

template ConfidentialTransfer(nBits) {
    signal input inputAmount;
    signal input outputAmount;
    signal input fee;
    signal input inputBlinding;
    signal input outputBlinding;
    
    signal output inputCommitment;
    signal output outputCommitment;
    signal output isValid;
    
    // 1. Range checks: ensure amounts are within valid range (0 to 2^nBits - 1)
    component inputRange = Num2Bits(nBits);
    inputRange.in <== inputAmount;
    
    component outputRange = Num2Bits(nBits);
    outputRange.in <== outputAmount;
    
    component feeRange = Num2Bits(nBits);
    feeRange.in <== fee;
    
    // 2. Balance equation: inputAmount = outputAmount + fee
    signal balanceCheck;
    balanceCheck <== inputAmount - outputAmount - fee;
    balanceCheck === 0;
    
    // 3. Compute Poseidon commitments (hash of amount and blinding)
    component inputPoseidon = Poseidon(2);
    inputPoseidon.inputs[0] <== inputAmount;
    inputPoseidon.inputs[1] <== inputBlinding;
    inputCommitment <== inputPoseidon.out;
    
    component outputPoseidon = Poseidon(2);
    outputPoseidon.inputs[0] <== outputAmount;
    outputPoseidon.inputs[1] <== outputBlinding;
    outputCommitment <== outputPoseidon.out;
    
    // 4. Output validity signal
    isValid <== 1;
}

component main {public [fee]} = ConfidentialTransfer(64);
