pragma circom 2.1.6;

include "/home/y.okura/zkp/circomlib/circuits/poseidon.circom";      // ポセイドンハッシュ
include "/home/y.okura/zkp/circomlib/circuits/bitify.circom";        // ビット列への変換
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Example () {
 

    var num =100;
    component hash[num][2];
    component bitify[num][2];
    var randSeq[num][254*2];
    for(var i = 0; i<num;i++){
        for(var j = 0; j<2;j++){
            hash[i][j] = Poseidon(2);
            hash[i][j].inputs[0] <== i;
            hash[i][j].inputs[1] <== j;
            bitify[i][j]= Num2Bits_strict();
            bitify[i][j].in<== hash[i][j].out;
            for(var l =0; l < 254; l++){
                 randSeq[i][j * 254 + l] = bitify[i][j].out[l];
            }
        }
    }
    var sum[num];
    for(var i = 0; i<num;i++){
        for(var j = 0; j<2;j++){
            for(var l =0; l < 254; l++){
                 sum[i] += randSeq[i][j * 254 + l];
            }
        }
    }
    signal output sum_o[num];
    for(var i = 0; i<num;i++){
        sum_o[i]<== sum[i];
    }


}

component main  = Example();
