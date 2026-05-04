pragma circom 2.0.0;
include "./templates/bigintEncryptVote.circom";
include "./templates/MerkleTreeChecker.circom";
include "./templates/NullifierHasher.circom";
include "./templates/CommitmentHasher.circom";
include "./templates/PublicSignalsHasherCastVote.circom";
//include "./templates/WordsHasher.circom";
include "./templates/hashInput.circom";







template castVote(n, kN, kr, lN, lr, MerkleTreeDepth){
    // assert(n <= 63);
    signal input N[kN];
    signal input g[kN];
    signal input h_pow_N[2 * kN];
    signal input merkleRoot;
    signal input relayerAddr;
    signal input fee;
    signal input u[kN];
    signal input v[2 * kN];
    signal input nullifierHash;
    
    signal input r[kr];
    signal input d;
    signal input proof[MerkleTreeDepth];
    signal input insertedIndex;
    signal input secret;
    signal input voterAddr;


    // signal output u;
    // signal output v;
    // signal output nullifierHasherOut;
    
    signal output publicSignalsHash;


    component commitmentHasher;
    commitmentHasher = commitmentHasher();
    commitmentHasher.secret <== secret;
    commitmentHasher.committerAddr <== voterAddr;

    component merkleTreeChecker;
    merkleTreeChecker = MerkleTreeChecker(MerkleTreeDepth);
    merkleTreeChecker.leaf <== commitmentHasher.out;
    merkleTreeChecker.root <== merkleRoot;
    merkleTreeChecker.insertedIndex <== insertedIndex;
    for(var i=0; i<MerkleTreeDepth;i++){
        merkleTreeChecker.pathElements[i] <== proof[i];
    }

    component encryptVote;
    
    encryptVote = EncryptVote2(n, kN, kr, lN, lr);
    for(var i=0;i<kN; i++){
        encryptVote.N[i] <== N[i];
        encryptVote.g[i] <== g[i];
    }
    for(var i=0;i<2 * kN; i++){
        encryptVote.h_pow_N[i] <== h_pow_N[i];
    }
    for(var i=0;i<kr; i++){
        encryptVote.r[i] <== r[i];
    }
    encryptVote.d <== d;
    for(var i=0;i<kN; i++){
        u[i] === encryptVote.u[i];
    }
    for(var i=0;i<2 * kN; i++){
        v[i] === encryptVote.v[i];
    }

    component nullifierHasher;
    nullifierHasher = NullifierHasher();
    nullifierHasher.secret <== secret;
    nullifierHasher.insertedIndex <== insertedIndex;
    nullifierHash === nullifierHasher.out;


    // signal relayerSquare;
    // signal feeSquare;
    // relayerSquare <== relayerAddr * relayerAddr;
    // feeSquare <== fee * fee;

    // component wordsHasher_N = WordsHasher(kN);
    // for(var i=0; i<kN; i++) {wordsHasher_N.words[i] <== N[i];} 
    // component wordsHasher_g = WordsHasher(kN);
    // for(var i=0; i<kN; i++) {wordsHasher_g.words[i] <== g[i];} 
    // // component wordsHasher_h = WordsHasher(kN); 
    // // for(var i=0; i<kN; i++) {wordsHasher_h.words[i] <== h[i];} 
    // component wordsHasher_h_pow_N = WordsHasher(2 * kN); 
    // for(var i=0; i<2*kN; i++) {wordsHasher_h_pow_N.words[i] <== h_pow_N[i];} 
    // component wordsHasher_u = WordsHasher(kN); 
    // for(var i=0; i<kN; i++) {wordsHasher_u.words[i] <== u[i];} 
    // component wordsHasher_v = WordsHasher(2 * kN); 
    // for(var i=0; i<2*kN; i++) {wordsHasher_v.words[i] <== v[i];} 

    // component publicSignalsHasher;
    // publicSignalsHasher = PublicSignalsHasher();
    // publicSignalsHasher.in[0] <== wordsHasher_N.out;
    // publicSignalsHasher.in[1] <== wordsHasher_g.out;
    // // publicSignalsHasher.in[2] <== wordsHasher_h.out;
    // publicSignalsHasher.in[2] <== wordsHasher_h_pow_N.out;
    // publicSignalsHasher.in[3] <== merkleRoot;
    // publicSignalsHasher.in[4] <== relayerAddr;
    // publicSignalsHasher.in[5] <== fee;
    // publicSignalsHasher.in[6] <== wordsHasher_u.out;
    // publicSignalsHasher.in[7] <== wordsHasher_v.out;
    // publicSignalsHasher.in[8] <== nullifierHash;
    // publicSignalsHash <== publicSignalsHasher.out;

    component hashInput = HashInputs(67);
        for(var i=0;i<9;i++){
            hashInput.in[i] <== N[i];    
        }
        for(var i=9;i<18;i++){
            hashInput.in[i] <== g[i-9];    
        }
        for(var i=18;i<36;i++){
            hashInput.in[i] <== h_pow_N[i-18];    
        }
        hashInput.in[36] <== merkleRoot;
        hashInput.in[37] <== relayerAddr;
        hashInput.in[38] <== fee;

        for(var i=39;i<48;i++){
            hashInput.in[i] <== u[i-39];    
        }
        for(var i=48;i<66;i++){
            hashInput.in[i] <== v[i-48];    
        }
        hashInput.in[66] <== nullifierHash;
        publicSignalsHash <== hashInput.out;    

}

// component main {public [N, g, h, merkleRoot, relayerAddr, fee]} = Main(63, 4);
