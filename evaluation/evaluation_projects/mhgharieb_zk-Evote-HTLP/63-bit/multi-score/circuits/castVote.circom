pragma circom 2.0.0;
include "./templates/encryptVote.circom";
include "./templates/MerkleTreeChecker.circom";
include "./templates/NullifierHasher.circom";
include "./templates/CommitmentHasher.circom";
include "./templates/PublicSignalsHasherCastVote.circom";
include "./templates/AggregatedVote.circom";


//k >= log_2 (S*n_v) + 1
template castVote(n, MerkleTreeDepth, nCandiadates, S, k){
    assert(n <= 63);
    assert(n > nCandiadates*k );
    signal input N;
    signal input g;
    signal input h;
    signal input merkleRoot;
    signal input relayerAddr;
    signal input fee;
    signal input u;
    signal input v;
    signal input nullifierHash;
    
    signal input r;
    signal input d[nCandiadates];
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

    
    component aggregatedVote;
    aggregatedVote = AggregatedVote(nCandiadates, S, k);
    for(var i=0; i<nCandiadates; i++){
        aggregatedVote.in_d[i] <== d[i];
    }

    component encryptVote;
    encryptVote = EncryptVote2(n, nCandiadates, k);
    encryptVote.N <== N;
    encryptVote.g <== g;
    encryptVote.h <== h;
    encryptVote.r <== r;
    encryptVote.d <== aggregatedVote.d;

    u === encryptVote.u;
    v === encryptVote.v;

    component nullifierHasher;
    nullifierHasher = NullifierHasher();
    nullifierHasher.secret <== secret;
    nullifierHasher.insertedIndex <== insertedIndex;
    nullifierHash === nullifierHasher.out;


    // signal relayerSquare;
    // signal feeSquare;
    // relayerSquare <== relayerAddr * relayerAddr;
    // feeSquare <== fee * fee;

    component publicSignalsHasher;
    publicSignalsHasher = PublicSignalsHasher();
    publicSignalsHasher.in[0] <== N;
    publicSignalsHasher.in[1] <== g;
    publicSignalsHasher.in[2] <== h;
    publicSignalsHasher.in[3] <== merkleRoot;
    publicSignalsHasher.in[4] <== relayerAddr;
    publicSignalsHasher.in[5] <== fee;
    publicSignalsHasher.in[6] <== u;
    publicSignalsHasher.in[7] <== v;
    publicSignalsHasher.in[8] <== nullifierHash;
    publicSignalsHash <== publicSignalsHasher.out;
}

// component main {public [N, g, h, merkleRoot, relayerAddr, fee]} = Main(63, 4);
