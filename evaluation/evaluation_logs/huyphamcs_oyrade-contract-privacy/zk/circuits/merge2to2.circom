// Merge 2→2 circuit for maximum flexibility
// This circuit can:
//   - Split: (100, 0) → (60, 40)
//   - Combine: (30, 20) → (50, 0) 
//   - Merge: (30, 25) → (45, 10)
//
// Public outputs:
//   n1, n2     : nullifiers of 2 spent input notes
//   leaf1, leaf2 : 2 output leaves
//   root       : Merkle root
//
// On-chain public_inputs format:
//   [0..32)    -> n1
//   [32..64)   -> n2
//   [64..96)   -> leaf1
//   [96..128)  -> leaf2
//   [128..160) -> root

pragma circom 2.2.3;

include "../lib/poseidon.circom";
include "../lib/merkle.circom";

template Merge2To2(depth) {
    // PUBLIC OUTPUTS
    signal output n1;
    signal output n2;
    signal output leaf1;
    signal output leaf2;
    signal output root;

    // PRIVATE INPUT NOTE 1 (spent)
    signal input in1Amount;
    signal input in1Nullifier;
    signal input in1AssetId;
    
    // PRIVATE INPUT NOTE 2 (spent)
    signal input in2Amount;
    signal input in2Nullifier;
    signal input in2AssetId;

    // PRIVATE OUTPUT NOTE 1 (created)
    signal input out1Amount;
    signal input out1Nullifier;
    signal input out1AssetId;

    // PRIVATE OUTPUT NOTE 2 (created)
    signal input out2Amount;
    signal input out2Nullifier;
    signal input out2AssetId;

    // Merkle paths for both input notes
    signal input path1Elements[depth];
    signal input path1Index[depth];
    
    signal input path2Elements[depth];
    signal input path2Index[depth];

    // --- Recompute input leaf 1 ---
    component hIn1 = Poseidon3();
    hIn1.in[0] <== in1Amount;
    hIn1.in[1] <== in1Nullifier;
    hIn1.in[2] <== in1AssetId;
    signal in1Leaf;
    in1Leaf <== hIn1.out;

    // --- Recompute input leaf 2 ---
    component hIn2 = Poseidon3();
    hIn2.in[0] <== in2Amount;
    hIn2.in[1] <== in2Nullifier;
    hIn2.in[2] <== in2AssetId;
    signal in2Leaf;
    in2Leaf <== hIn2.out;

    // --- Enforce membership of both input leaves in same tree ---
    component merkle1 = MerkleMembership(depth);
    merkle1.leaf <== in1Leaf;
    for (var i = 0; i < depth; i++) {
        merkle1.pathElements[i] <== path1Elements[i];
        merkle1.pathIndex[i] <== path1Index[i];
    }

    component merkle2 = MerkleMembership(depth);
    merkle2.leaf <== in2Leaf;
    for (var i = 0; i < depth; i++) {
        merkle2.pathElements[i] <== path2Elements[i];
        merkle2.pathIndex[i] <== path2Index[i];
    }

    // Both inputs must be in the same tree
    merkle1.root === merkle2.root;
    root <== merkle1.root;

    // --- Recompute output leaves ---
    component hOut1 = Poseidon3();
    hOut1.in[0] <== out1Amount;
    hOut1.in[1] <== out1Nullifier;
    hOut1.in[2] <== out1AssetId;
    leaf1 <== hOut1.out;

    component hOut2 = Poseidon3();
    hOut2.in[0] <== out2Amount;
    hOut2.in[1] <== out2Nullifier;
    hOut2.in[2] <== out2AssetId;
    leaf2 <== hOut2.out;

    // --- Output nullifiers ---
    n1 <== in1Nullifier;
    n2 <== in2Nullifier;

    // --- CRITICAL CONSTRAINTS ---
    
    // 1. Value conservation: Total input = Total output
    in1Amount + in2Amount === out1Amount + out2Amount;

    // 2. Asset type must be consistent
    in1AssetId === in2AssetId;
    in1AssetId === out1AssetId;
    in1AssetId === out2AssetId;

    // 3. Nullifiers must be unique (prevents using same note twice)
    // To prove a != b, we prove (a - b) is non-zero by computing its inverse
    signal nullifierDiff;
    nullifierDiff <== in1Nullifier - in2Nullifier;
    
    // Compute inverse of diff (only possible if diff != 0)
    signal nullifierDiffInv;
    nullifierDiffInv <-- 1 / nullifierDiff;  // Hint: compute inverse
    
    // Constraint: diff * inv === 1 (fails if diff is 0)
    nullifierDiff * nullifierDiffInv === 1;
}

component main = Merge2To2(30);
