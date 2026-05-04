pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../merkleTree.circom";

////////////////////////////////////////////
// Circuit goals: 
//  - prove leaf is in tree
//  - prove hash(secret) is leaf
//  - compute msgAttestation = hash(salt, secret, msg)
//  - msg is mimc hash of message.
////////////////////////////////////////////

template Reveal(levels) {

    // inputs for LeafExists
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input leaf;

    // inputs for msgAttestation
    signal input secret;
    signal input salt;
    signal input msg;
    signal input msgAttestation;

    var i;
    var j;

    // proof leaf exists in root
    component verifier = MerkleTreeChecker(levels);
    verifier.leaf <== leaf;
    verifier.root <== root;
    for (i = 0; i < levels; i ++) {
        verifier.pathElements[i] <== pathElements[i];
        verifier.pathIndices[i] <== pathIndices[i];
    }

    // proof secret == leaf
    component hash1 = MiMCSponge(1,220,1);
    hash1.k <== 0;
    hash1.ins[0] <== secret;
    hash1.outs[0] === leaf;

    component hash2 = MiMCSponge(3,220,1);
    hash2.k <== 0;
    hash2.ins[0] <== salt;
    hash2.ins[1] <== secret;
    hash2.ins[2] <== salt;
    msgAttestation === hash2.outs[0]; 
}

component main {public [msgAttestation, leaf, msg, root]} = Reveal(9);