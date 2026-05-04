
//eps = 8
    // 必要な乱数列の数 = 28
    // 必要な乱数列の長さ = 64
    // 28 * 64 = 1792ビット
    // ハッシュ列の長さ 254 //256とする
    // ハッシュへのアクセス回数 7回

pragma circom 2.1.6;
include "/home/y.okura/zkp/circomlib/circuits/eddsaposeidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/poseidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/bitify.circom";
include "/home/y.okura/zkp/circomlib/circuits/absoluter.circom";

    // 乱数列の数 = 28
    // 必要な乱数列の長さ 64
    // 28 * 64 = 1792ビット
    // ハッシュ列の長さ 254 //256とする
    // ハッシュへのアクセス回数 7回
    

template Main (out_dim, in_dim, S_clip, sigma, num_tosses) {
    signal input W_delta[out_dim][in_dim];
    signal input challenge; //チャレンジの値
    signal input R8[2];
    signal input S;
    signal input pk[2];
　
    component eddsaVerifier = EdDSAPoseidonVerifier();
        eddsaVerifier.Ax <== pk[0];
        eddsaVerifier.Ay <== pk[1];
        eddsaVerifier.S <== S;
        eddsaVerifier.R8x <== R8[0];
        eddsaVerifier.R8y <== R8[1];
        eddsaVerifier.M <== challenge;
        eddsaVerifier.enabled <== 1;
  
    component hash[7];
    component bitify[7];

    for(var i = 0; i<7;i++){
        hash[i]=Poseidon(4);
        hash[i].inputs[0] <== R8[0];
        hash[i].inputs[1] <== R8[1];
        hash[i].inputs[2] <== S;
        hash[i].inputs[3] <== i;
        bitify[i]= Num2Bits_strict();
        bitify[i].in <== hash[i].out;
    }
         
    var randSeq[256 * 7];
    for(var i =0; i < 7; i++){
       for(var j = 0; j < 254; j++){
           randSeq[256*i + j]= bitify[i].out[j];
        }
           randSeq[256*i + 254]= 0;
           randSeq[256*i + 255]= 0;
    }
    var binom_val[out_dim][in_dim];

    for(var i =0; i < out_dim; i++){
        for(var j = 0; j < in_dim; j++){
            for(var k = 0; k < 64; k++){
                binom_val[i][j] += randSeq[k + 64 * (out_dim * i + j)];
            }
        }
    }

   var noize[out_dim][in_dim];
   var binom_mean =  32;
   var binom_deviation = 4; 
   for(var i =0; i < out_dim; i++){
       for(var j = 0; j < in_dim; j++){
           noize[i][j] = binom_val[i][j] - binom_mean;
       }
   }

  var W_norm = 0;
  component abs[out_dim][in_dim];
  for(var i = 0; i < out_dim; i++){
      for(var j = 0; j < in_dim; j++){
          abs[i][j] = Num2abs();
          abs[i][j].in <== W_delta[i][j];
          W_norm += abs[i][j].out;
      }
   }

  assert(W_norm < S_clip);
   signal output W_noised[out_dim][in_dim];
   for(var i =0; i < out_dim; i++){
       for(var j = 0; j < in_dim; j++){
           noize[i][j] *= S_clip;
           noize[i][j] *= sigma;
           W_noised[i][j] <== W_delta[i][j]* binom_deviation + noize[i][j];
       }
   }

}


component main {public [ challenge,pk ] } = Main(4,7,8000000,10000,64);