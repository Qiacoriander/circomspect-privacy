pragma circom 2.0.0;
include "./templates/encryptVote.circom";
include "./templates/AggregatedVote.circom";

template castVote(n, nCandiadates, S, k){
    assert(n <= 63);
    assert(n > nCandiadates*k );
    signal input N;
    signal input g;
    signal input h;    
    signal input r;
    signal input d[nCandiadates];

    signal output u;
    signal output v;


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
}