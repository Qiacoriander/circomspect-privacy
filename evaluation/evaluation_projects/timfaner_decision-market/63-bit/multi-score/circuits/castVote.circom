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
    signal input x[nCandiadates];
    signal output u;
    signal output v_d1;
    signal output v_d2;
    signal output v_x;

    component aggregatedVote_x;
    aggregatedVote_x = AggregatedVote(nCandiadates, 1, k);
    for(var i=0; i<nCandiadates; i++){
        aggregatedVote_x.in_d[i] <== x[i];
    }

    component encryptVote_x;
    encryptVote_x = EncryptVote2(n, nCandiadates, k);
    encryptVote_x.N <== N;
    encryptVote_x.g <== g;
    encryptVote_x.h <== h;
    encryptVote_x.r <== r;
    encryptVote_x.d <== aggregatedVote_x.d;
    v_x <== encryptVote_x.v;


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

    u <== encryptVote.u;
    v_d1 <== encryptVote.v;

    component encryptVoteMTH;
    encryptVoteMTH = EncryptVoteMTHLP(n, nCandiadates, k);
    encryptVoteMTH.N <== N;
    encryptVoteMTH.g <== g;
    encryptVoteMTH.h <== h;
    encryptVoteMTH.r <== r;
    encryptVoteMTH.d <== aggregatedVote.d;

    v_d2 <== encryptVoteMTH.v;
}
