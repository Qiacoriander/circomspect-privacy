pragma circom 2.1.0;

include "../lib/poseidon.circom";
include "../lib/merkle.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * CollateralProof Circuit
 *
 * Proves that a user has sufficient collateral to borrow a specified amount
 * without revealing the actual collateral amount.
 *
 * The circuit verifies:
 * 1. The commitment exists in the Merkle tree (ownership proof)
 * 2. collateralAmount * oraclePrice * ltvRatio >= loanAmount * 100
 *
 * Public Inputs:
 *   - merkleRoot: Root of the collateral commitment Merkle tree
 *   - loanAmount: Amount the user wants to borrow (scaled by 10^decimals)
 *   - ltvRatio: Loan-to-Value ratio (percentage, e.g., 75 for 75%)
 *   - oraclePrice: Price of collateral in loan token units (scaled)
 *
 * Private Inputs:
 *   - collateralAmount: Actual collateral amount deposited
 *   - nullifier: Secret nullifier for the commitment
 *   - pathElements: Merkle proof path elements
 *   - pathIndices: Merkle proof path indices (0 = left, 1 = right)
 *
 * Constants:
 *   - TREE_DEPTH: Depth of the Merkle tree (20 levels = ~1M leaves)
 */

template CollateralProof(TREE_DEPTH) {
    // Public inputs
    signal input merkleRoot;
    signal input loanAmount;
    signal input ltvRatio;      // e.g., 75 for 75% LTV
    signal input oraclePrice;   // Price scaled appropriately

    // Private inputs
    signal input collateralAmount;
    signal input nullifier;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];

    // Output: nullifier hash for double-spend prevention
    signal output nullifierHash;

    // ========== STEP 1: Compute commitment ==========
    // commitment = Poseidon(nullifier, collateralAmount)
    component commitmentHasher = PoseidonHash2();
    commitmentHasher.in[0] <== nullifier;
    commitmentHasher.in[1] <== collateralAmount;
    signal commitment;
    commitment <== commitmentHasher.out;

    // ========== STEP 2: Verify Merkle inclusion ==========
    // Prove that the commitment exists in the tree with the given root
    component merkleVerifier = MerkleTreeVerifier(TREE_DEPTH);
    merkleVerifier.leaf <== commitment;
    merkleVerifier.root <== merkleRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    // ========== STEP 3: Verify LTV constraint ==========
    // collateralAmount * oraclePrice * ltvRatio >= loanAmount * 100
    // This ensures the loan is sufficiently collateralized

    // Calculate: collateralValue = collateralAmount * oraclePrice
    signal collateralValue;
    collateralValue <== collateralAmount * oraclePrice;

    // Calculate: maxBorrowValue = collateralValue * ltvRatio
    signal maxBorrowValue;
    maxBorrowValue <== collateralValue * ltvRatio;

    // Calculate: requiredValue = loanAmount * 100
    signal requiredValue;
    requiredValue <== loanAmount * 100;

    // Verify: maxBorrowValue >= requiredValue
    // Using LessEqThan with sufficient bits for large values
    // Assuming values up to 2^128 (enough for most DeFi amounts)
    component ltv_check = LessEqThan(128);
    ltv_check.in[0] <== requiredValue;
    ltv_check.in[1] <== maxBorrowValue;
    ltv_check.out === 1;

    // ========== STEP 4: Compute nullifier hash ==========
    // Used to prevent double-spending of the same commitment
    component nullifierHasher = PoseidonHash2();
    nullifierHasher.in[0] <== nullifier;
    nullifierHasher.in[1] <== commitment;
    nullifierHash <== nullifierHasher.out;

    // ========== STEP 5: Range checks ==========
    // Ensure all amounts are positive and within valid range

    // collateralAmount must be positive (non-zero)
    component collateralPositive = GreaterThan(128);
    collateralPositive.in[0] <== collateralAmount;
    collateralPositive.in[1] <== 0;
    collateralPositive.out === 1;

    // loanAmount must be positive
    component loanPositive = GreaterThan(128);
    loanPositive.in[0] <== loanAmount;
    loanPositive.in[1] <== 0;
    loanPositive.out === 1;

    // ltvRatio must be between 1 and 100 (inclusive)
    component ltvMin = GreaterEqThan(8);
    ltvMin.in[0] <== ltvRatio;
    ltvMin.in[1] <== 1;
    ltvMin.out === 1;

    component ltvMax = LessEqThan(8);
    ltvMax.in[0] <== ltvRatio;
    ltvMax.in[1] <== 100;
    ltvMax.out === 1;

    // oraclePrice must be positive
    component pricePositive = GreaterThan(128);
    pricePositive.in[0] <== oraclePrice;
    pricePositive.in[1] <== 0;
    pricePositive.out === 1;
}

// Main component with 20-level Merkle tree (supports ~1M deposits)
component main {public [merkleRoot, loanAmount, ltvRatio, oraclePrice]} = CollateralProof(20);
