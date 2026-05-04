pragma circom 2.2.0;

include "./utils/mimc5.circom";

template Verifier() {
    signal input root;
    signal input prevBlockHash;
    signal input nextBlocksRootTree[256];
    signal input currentBlockTreeRoots[10];
    signal input finalBlockHash;
    signal input securityBlockTreeRoots[512];
    signal output isValid;

    // Check if root exists in currentBlockTreeRoots

    var c = 0;
    signal contains <== 1;
    signal blockTreeRootHash[10];
    blockTreeRootHash[0] <== currentBlockTreeRoots[0];
    
    component treeHasher[9];
    for (var i = 1; i < 10; i++) {
        c += (currentBlockTreeRoots[i] == root) ? 1 : 0;
       
        treeHasher[i-1] = MiMC5Sponge(2);
        treeHasher[i-1].ins[0] <== blockTreeRootHash[i-1];
        treeHasher[i-1].ins[1] <== currentBlockTreeRoots[i];
        treeHasher[i-1].k <== 0;
        blockTreeRootHash[i] <== treeHasher[i-1].o;
    }

    // Process nextBlocksRootTree (fixed loop)
    signal curTreeHash[769];
    signal prevBlock[769];
    signal isNonZero[769];
    signal isValidFinalHash[768];

    prevBlock[0] <== prevBlockHash;
    curTreeHash[0] <== blockTreeRootHash[9];
    var nextCounter = 0;
    component nextHasher[256];
    component finalHasher[768];

    var finalHashV = 0;
    signal validFinalHash <== 1;

    for (var i = 0; i < 256; i++) {
        nextHasher[i] =  MiMC5Sponge(2);
        nextHasher[i].ins[0] <== prevBlock[i];
        nextHasher[i].ins[1] <== curTreeHash[i];
        nextHasher[i].k <== 0;
        prevBlock[i+1] <== nextHasher[i].o;
        curTreeHash[i+1] <== nextBlocksRootTree[i];

        // Verify finalBlockHash
        finalHasher[i] = MiMC5Sponge(2);
        finalHasher[i].ins[0] <== prevBlock[i];
        finalHasher[i].ins[1] <== curTreeHash[i];
        finalHasher[i].k <== 0;

        finalHashV += (finalHasher[i].o == finalBlockHash) ? 1 : 0;
    }

    // Process securityBlockTreeRoots (fixed loop)
    var j = 0;
    var secCounter = 0;
    component secHasher[512];
    for (var i = 256; i < 767; i++) {
        secHasher[j] =  MiMC5Sponge(2);
        secHasher[j].ins[0] <== prevBlock[i];
        secHasher[j].ins[1] <== curTreeHash[i];
        secHasher[j].k <== 0;
        prevBlock[i+1] <== secHasher[j].o;
        curTreeHash[i+1] <== securityBlockTreeRoots[j];

        // Verify finalBlockHash
        finalHasher[i] = MiMC5Sponge(2);
        finalHasher[i].ins[0] <== prevBlock[i];
        finalHasher[i].ins[1] <== curTreeHash[i];
        finalHasher[i].k <== 0;

        finalHashV += (finalHasher[i].o == finalBlockHash) ? 1 : 0;
        j++;  
    }

    isValid <-- (c + finalHashV) == 2? 1:0; 
}
