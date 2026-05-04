pragma circom 2.2.0;

// Got this from https://github.com/Shigoto-dev19/classic-elgamal-circom


include "../node_modules/circomlib/circuits/poseidon.circom";

include "./classic_encrypt.circom";

template Adder(n) {
  signal input in[n];
  signal output out;

  var lc = 0;
  for (var i = 0; i < n; i++) {
    lc += in[i];
  }
  out <== lc;
}

template ArrayRead(n) {
  signal input in[n];
  signal input index;
  signal output out;

  signal intermediate[n];
  for (var i = 0; i < n; i++) {
    var isIndex = IsEqual()([index, i]);
    intermediate[i] <== isIndex * in[i];
  }

  out <== Adder(n)(intermediate);
}
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    // @dev 220 seems to be the recommended value ?
    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

// @dev leafCount = 2**levels
// @dev nodeCount = 2**(levels - 1)
template MerkleTreeLevel(leafCount, nodeCount) {
    signal input leaves[leafCount];
    signal output nodes[nodeCount];

    // check amounts are valid
    leafCount === 2*nodeCount;

    component hashers[nodeCount];

    var i = 0;
    var n = 0;
    while(i < nodeCount){
       hashers[i] = HashLeftRight();
       hashers[i].left <== leaves[n]; 
       hashers[i].right <== leaves[n + 1];
   
       nodes[i] <== hashers[i].hash;

       i++;
       n+=2;
    }
}


// @dev leafCount = 2**levels
// @dev result is sensitive to the order of leaves
template MerkleTree(levels){
    signal input leaves[2**levels];
    signal output root;

    component merkleLevels[levels]; 

    // @dev iterate over each level of the tree. 
    var i = 0;
    while(i < levels){
        var leafCount = 2**(levels - i);
        var nodeCount = 2**(levels - i - 1);

        merkleLevels[i] = MerkleTreeLevel(leafCount, nodeCount); 
    
        var n = 0;
        while(n < leafCount){
            merkleLevels[i].leaves[n] <== i == 0 ? leaves[n] : merkleLevels[i - 1].nodes[n];

            n++;
        }

        
        i++;
    }

    root <== merkleLevels[levels - 1].nodes[0];
}

template GenerateJurry(juryNum, potentialJuryNum, levels) {
    signal input publicKey;
    signal input nonce;
    signal input randomValue;
    signal input allPotentialJuries[potentialJuryNum];
    signal input jurorIndices[juryNum];

    signal output merkleRoot;
    signal jury[juryNum];
    signal output juryEnc[juryNum];
    signal output juryEphemeral[juryNum];

    component encrypters[juryNum];
    for(var i =0; i<juryNum; i++){
        jury[i] <== ArrayRead(potentialJuryNum)(allPotentialJuries,jurorIndices[i]);
        encrypters[i] = Encrypt_Classic();
        encrypters[i].secret <== jury[i];
        encrypters[i].publicKey <== publicKey;
        encrypters[i].nonce <== nonce + i;
        juryEnc[i] <== encrypters[i].encryptedMessage;
        juryEphemeral[i] <== encrypters[i].ephemeralKey;
    }

    var ceilpow = 2**levels;
    var curLevel[ceilpow];

    for (var i = 0; i < juryNum; i++) {
        curLevel[i] = jury[i];
    }

    merkleRoot <== MerkleTree(levels)(curLevel);
    
}

component main { public [publicKey, randomValue]} = GenerateJurry(11, 100, 5); 


