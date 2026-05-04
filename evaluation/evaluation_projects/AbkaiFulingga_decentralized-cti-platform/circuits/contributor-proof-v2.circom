pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * Enhanced Contributor Proof Circuit with Context Binding
 * 
 * This circuit proves that a contributor is registered without revealing their identity,
 * with additional context binding to prevent cross-chain and cross-contract replay attacks.
 * 
 * Public Inputs:
 *   - commitment: Hash of (address, nonce) - identifies this submission
 *   - merkleRoot: Root of contributor Merkle tree
 *   - chainId: Blockchain chain ID (e.g., 421614 for Arbitrum Sepolia)
 *   - contractAddress: Target contract address
 * 
 * Private Inputs:
 *   - address: Contributor's Ethereum address
 *   - nonce: Random value for commitment
 *   - merkleProof: Proof that address is in contributor tree
 *   - merklePathIndices: Path indices for Merkle proof
 * 
 * Proves:
 *   1. commitment = Poseidon(address, nonce, chainId, contractAddress)
 *   2. address exists in Merkle tree with root merkleRoot
 *   3. Proof is bound to specific chain and contract
 *   4. Without revealing actual address
 */

template MerkleTreeInclusionProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    component mux[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Select left/right based on path index
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];

        mux[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[levels];
}

template MultiMux1(n) {
    signal input c[n][2];
    signal input s;
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== c[i][0] + s * (c[i][1] - c[i][0]);
    }
}

template ContributorProofWithContext(merkleTreeLevels) {
    // Public inputs (visible on-chain)
    signal input commitment;
    signal input merkleRoot;
    signal input chainId;           // NEW: Chain ID binding
    signal input contractAddress;   // NEW: Contract binding

    // Private inputs (hidden)
    signal input address;
    signal input nonce;
    signal input merkleProof[merkleTreeLevels];
    signal input merklePathIndices[merkleTreeLevels];

    // Verify commitment = Poseidon(address, nonce, chainId, contractAddress)
    // This binds the proof to a specific chain and contract
    component commitmentHasher = Poseidon(4);
    commitmentHasher.inputs[0] <== address;
    commitmentHasher.inputs[1] <== nonce;
    commitmentHasher.inputs[2] <== chainId;
    commitmentHasher.inputs[3] <== contractAddress;
    commitment === commitmentHasher.out;

    // Verify address is in Merkle tree
    component merkleChecker = MerkleTreeInclusionProof(merkleTreeLevels);
    merkleChecker.leaf <== address;
    for (var i = 0; i < merkleTreeLevels; i++) {
        merkleChecker.pathElements[i] <== merkleProof[i];
        merkleChecker.pathIndices[i] <== merklePathIndices[i];
    }
    merkleRoot === merkleChecker.root;

    // Constraint: address must be non-zero (valid Ethereum address)
    component isZero = IsZero();
    isZero.in <== address;
    isZero.out === 0;

    // Constraint: chainId must be non-zero (valid chain)
    component isChainZero = IsZero();
    isChainZero.in <== chainId;
    isChainZero.out === 0;

    // Constraint: contractAddress must be non-zero (valid contract)
    component isContractZero = IsZero();
    isContractZero.in <== contractAddress;
    isContractZero.out === 0;

    // Additional security: Verify nonce is reasonable (not too large)
    // This prevents integer overflow attacks
    component nonceBits = Num2Bits(64);
    nonceBits.in <== nonce;
}

// Main component with 20 levels (supports 2^20 = 1M contributors)
component main {public [commitment, merkleRoot, chainId, contractAddress]} = ContributorProofWithContext(20);
