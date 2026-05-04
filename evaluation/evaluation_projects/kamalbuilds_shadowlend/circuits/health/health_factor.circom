pragma circom 2.1.0;

include "../lib/poseidon.circom";
include "../lib/merkle.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * HealthFactorProof Circuit
 *
 * Proves that a position's health factor is below 1 (liquidatable)
 * without revealing the actual collateral or debt amounts.
 *
 * Health Factor = (collateralValue * liquidationThreshold) / debtValue
 * Position is liquidatable when Health Factor < 1
 *
 * The circuit proves:
 * collateralValue * liquidationThreshold < debtValue * 100
 *
 * Public Inputs:
 *   - merkleRoot: Root of the positions Merkle tree
 *   - liquidationThreshold: Liquidation threshold percentage (e.g., 80 for 80%)
 *   - oraclePriceCollateral: Price of collateral asset
 *   - oraclePriceDebt: Price of debt asset
 *
 * Private Inputs:
 *   - collateralAmount: Actual collateral amount
 *   - debtAmount: Current debt amount including interest
 *   - nullifier: Secret nullifier for the position
 *   - pathElements: Merkle proof path elements
 *   - pathIndices: Merkle proof path indices
 */

template HealthFactorProof(TREE_DEPTH) {
    // Public inputs
    signal input merkleRoot;
    signal input liquidationThreshold;      // e.g., 80 for 80%
    signal input oraclePriceCollateral;     // Price of collateral token
    signal input oraclePriceDebt;           // Price of debt token

    // Private inputs
    signal input collateralAmount;
    signal input debtAmount;
    signal input nullifier;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];

    // Output: position identifier for liquidation tracking
    signal output positionHash;

    // ========== STEP 1: Compute position commitment ==========
    // commitment = Poseidon(nullifier, collateralAmount, debtAmount)
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== collateralAmount;
    commitmentHasher.inputs[2] <== debtAmount;
    signal commitment;
    commitment <== commitmentHasher.out;

    // ========== STEP 2: Verify Merkle inclusion ==========
    component merkleVerifier = MerkleTreeVerifier(TREE_DEPTH);
    merkleVerifier.leaf <== commitment;
    merkleVerifier.root <== merkleRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    // ========== STEP 3: Compute values in common denomination ==========
    // collateralValue = collateralAmount * oraclePriceCollateral
    signal collateralValue;
    collateralValue <== collateralAmount * oraclePriceCollateral;

    // debtValue = debtAmount * oraclePriceDebt
    signal debtValue;
    debtValue <== debtAmount * oraclePriceDebt;

    // ========== STEP 4: Verify Health Factor < 1 ==========
    // Health Factor < 1 means:
    // (collateralValue * liquidationThreshold / 100) < debtValue
    // Rearranged to avoid division:
    // collateralValue * liquidationThreshold < debtValue * 100

    signal adjustedCollateralValue;
    adjustedCollateralValue <== collateralValue * liquidationThreshold;

    signal adjustedDebtValue;
    adjustedDebtValue <== debtValue * 100;

    // Verify: adjustedCollateralValue < adjustedDebtValue
    // This proves health factor is below 1 (position is liquidatable)
    component healthCheck = LessThan(128);
    healthCheck.in[0] <== adjustedCollateralValue;
    healthCheck.in[1] <== adjustedDebtValue;
    healthCheck.out === 1;

    // ========== STEP 5: Compute position hash ==========
    // Used to track which position is being liquidated
    component positionHasher = PoseidonHash2();
    positionHasher.in[0] <== nullifier;
    positionHasher.in[1] <== commitment;
    positionHash <== positionHasher.out;

    // ========== STEP 6: Range checks ==========
    // Ensure debt is non-zero (can't liquidate zero-debt position)
    component debtPositive = GreaterThan(128);
    debtPositive.in[0] <== debtAmount;
    debtPositive.in[1] <== 0;
    debtPositive.out === 1;

    // liquidationThreshold must be between 1 and 100
    component thresholdMin = GreaterEqThan(8);
    thresholdMin.in[0] <== liquidationThreshold;
    thresholdMin.in[1] <== 1;
    thresholdMin.out === 1;

    component thresholdMax = LessEqThan(8);
    thresholdMax.in[0] <== liquidationThreshold;
    thresholdMax.in[1] <== 100;
    thresholdMax.out === 1;

    // Oracle prices must be positive
    component priceCollateralPositive = GreaterThan(128);
    priceCollateralPositive.in[0] <== oraclePriceCollateral;
    priceCollateralPositive.in[1] <== 0;
    priceCollateralPositive.out === 1;

    component priceDebtPositive = GreaterThan(128);
    priceDebtPositive.in[0] <== oraclePriceDebt;
    priceDebtPositive.in[1] <== 0;
    priceDebtPositive.out === 1;
}

/*
 * HealthFactorRangeProof Circuit
 *
 * Proves that a position's health factor is within a specific range
 * without revealing exact amounts. Useful for partial liquidations.
 *
 * Proves: minHF <= healthFactor < maxHF
 */

template HealthFactorRangeProof(TREE_DEPTH) {
    // Public inputs
    signal input merkleRoot;
    signal input liquidationThreshold;
    signal input oraclePriceCollateral;
    signal input oraclePriceDebt;
    signal input minHealthFactorBps;    // Minimum HF in basis points (e.g., 5000 = 0.5)
    signal input maxHealthFactorBps;    // Maximum HF in basis points (e.g., 10000 = 1.0)

    // Private inputs
    signal input collateralAmount;
    signal input debtAmount;
    signal input nullifier;
    signal input pathElements[TREE_DEPTH];
    signal input pathIndices[TREE_DEPTH];

    // Output
    signal output positionHash;

    // Compute commitment
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== nullifier;
    commitmentHasher.inputs[1] <== collateralAmount;
    commitmentHasher.inputs[2] <== debtAmount;
    signal commitment;
    commitment <== commitmentHasher.out;

    // Verify Merkle inclusion
    component merkleVerifier = MerkleTreeVerifier(TREE_DEPTH);
    merkleVerifier.leaf <== commitment;
    merkleVerifier.root <== merkleRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }

    // Calculate health factor components
    // HF = (collateralValue * liquidationThreshold) / (debtValue * 100)
    // HF in bps = (collateralValue * liquidationThreshold * 10000) / (debtValue * 100)
    // Simplified: HF_bps * debtValue * 100 = collateralValue * liquidationThreshold * 10000

    signal collateralValue;
    collateralValue <== collateralAmount * oraclePriceCollateral;

    signal debtValue;
    debtValue <== debtAmount * oraclePriceDebt;

    // For minHF check: collateralValue * liquidationThreshold * 10000 >= minHF * debtValue * 100
    signal leftSide;
    leftSide <== collateralValue * liquidationThreshold;

    signal minRight;
    minRight <== minHealthFactorBps * debtValue;

    // Verify HF >= minHF
    // leftSide * 10000 >= minRight * 100
    // leftSide * 100 >= minRight
    signal scaledLeft;
    scaledLeft <== leftSide * 100;

    component minCheck = GreaterEqThan(128);
    minCheck.in[0] <== scaledLeft;
    minCheck.in[1] <== minRight;
    minCheck.out === 1;

    // Verify HF < maxHF
    signal maxRight;
    maxRight <== maxHealthFactorBps * debtValue;

    component maxCheck = LessThan(128);
    maxCheck.in[0] <== scaledLeft;
    maxCheck.in[1] <== maxRight;
    maxCheck.out === 1;

    // Compute position hash
    component positionHasher = PoseidonHash2();
    positionHasher.in[0] <== nullifier;
    positionHasher.in[1] <== commitment;
    positionHash <== positionHasher.out;

    // Debt must be positive
    component debtPositive = GreaterThan(128);
    debtPositive.in[0] <== debtAmount;
    debtPositive.in[1] <== 0;
    debtPositive.out === 1;
}

// Main component - basic health factor proof for liquidation
component main {public [merkleRoot, liquidationThreshold, oraclePriceCollateral, oraclePriceDebt]} = HealthFactorProof(20);
