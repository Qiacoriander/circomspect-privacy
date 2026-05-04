pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mimcsponge.circom";

template MiMCN(N) {
    signal input a;
    signal output out;

    component mimc[N];

    var k = 1;
    mimc[0] = MiMCSponge(1, 220, 1); // amount of rounds
    mimc[0].ins[0] <== a;
    mimc[0].k <== k;
    
    var j;
    for (j=1; j<N; j++) {
        mimc[j] = MiMCSponge(1, 220, 1);
        mimc[j].ins[0] <== mimc[j-1].outs[0];
        mimc[j].k <== k;
    }
    
    out <== mimc[j-1].outs[0];
}

component main = MiMCN(1);
