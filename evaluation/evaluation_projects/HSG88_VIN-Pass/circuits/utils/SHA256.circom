include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

template SHA256(N){

    signal input in[N];
    signal output out;
    component sha256 = Sha256(N*256);
    component n2b[N];
    
    for(var i=0; i<N; i++) {
        n2b[i] = Num2Bits(256);
        n2b[i].in <== in[i];
        for(var j=0; j<256; j++) 
            sha256.in[256*(i+1) -1 -j] <== n2b[i].out[j];
    }
    component b2n = Bits2Num(256);
    for (var i = 0; i < 256; i++) {
        b2n.in[i] <== sha256.out[255-i];
    }
    out <== b2n.out;
}
