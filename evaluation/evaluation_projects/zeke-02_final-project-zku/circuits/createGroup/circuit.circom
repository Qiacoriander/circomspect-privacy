pragma circom 2.0.0;

include "../merkleTree.circom";

////////////////////////////////////////////
// Circuit goals: 
//  - Prove root and leaves are correct for an MerkleTree
////////////////////////////////////////////

component main{ public [root]} = MerkleTreeChecker(9);