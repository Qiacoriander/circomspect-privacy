pragma circom 2.0.0;

/**
 * NFT Rarity Circuit
 * Verifies the rarity computation: R_i = (demand * Φ_i) / (supply + 1)
 */
template NFTRarity() {
    signal input demand;
    signal input phiValue;
    signal input supply;
    signal output rarityScore;
    
    // Intermediate signals
    signal demandPhiProduct;
    signal supplyPlusOne;
    
    // Calculate demand * Φ_i
    demandPhiProduct <== demand * phiValue;
    
    // Calculate supply + 1
    supplyPlusOne <== supply + 1;
    
    // Calculate rarity: (demand * Φ_i) / (supply + 1)
    rarityScore <== demandPhiProduct / supplyPlusOne;
}

/**
 * Batch NFT Rarity Verification
 * Verifies multiple NFT rarity scores
 */
template BatchNFTRarity(n) {
    signal input demands[n];
    signal input phiValues[n];
    signal input supplies[n];
    signal output rarityScores[n];
    
    component rarityCheckers[n];
    
    for (var i = 0; i < n; i++) {
        rarityCheckers[i] = NFTRarity();
        rarityCheckers[i].demand <== demands[i];
        rarityCheckers[i].phiValue <== phiValues[i];
        rarityCheckers[i].supply <== supplies[i];
        rarityScores[i] <== rarityCheckers[i].rarityScore;
    }
}

/**
 * Main component for single NFT verification
 */
component main {public [demand, phiValue, supply]} = NFTRarity();
