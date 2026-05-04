
//eps = 1

//完成済み

    // 必要な乱数列の数 = 28
    // 28 * 486 = 13608ビット
    // ハッシュ列の長さ 254
    // ハッシュへのアクセス回数 54回

pragma circom 2.1.6;
include "/home/y.okura/zkp/circomlib/circuits/eddsaposeidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/poseidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/bitify.circom";
include "/home/y.okura/zkp/circomlib/circuits/absoluter.circom";

template Main (out_dim, in_dim, S_clip, sigma) {
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
  
    var num_iterations = 2;
    component hash[out_dim][in_dim][num_iterations];
    component bitify[out_dim][in_dim][num_iterations];

    for(var i = 0; i < out_dim; i++){
        for(var j = 0; j < in_dim; j++){
            for(var k = 0; k < num_iterations; k++){
                hash[i][j][k]=Poseidon(5);
                hash[i][j][k].inputs[0] <== R8[0];
                hash[i][j][k].inputs[1] <== R8[1];
                hash[i][j][k].inputs[2] <== S;
                hash[i][j][k].inputs[3] <== i * out_dim + j;
                hash[i][j][k].inputs[4] <== k;
                bitify[i][j][k]= Num2Bits_strict();
                bitify[i][j][k].in <== hash[i][j][k].out;
            }
        }
    }
   
    var hash_len = 254;
    var randSeq[out_dim][in_dim][hash_len * num_iterations];
    for(var i =0; i < out_dim; i++){
       for(var j = 0; j < in_dim; j++){
           for(var k =0; k < num_iterations; k++){
               for(var l =0; l < hash_len; l++){
                   randSeq[i][j][k * hash_len + l] = bitify[i][j][k].out[l];
                }
            }
        }
    }
    var binom_val[out_dim][in_dim];
 
    for(var i =0; i < out_dim; i++){
        for(var j = 0; j < in_dim; j++){
            for(var k = 0; k < hash_len * num_iterations; k++){
                binom_val[i][j] += randSeq[i][j][k];
            }
        }
    }

   var noize[out_dim][in_dim];
   var binom_mean = hash_len * num_iterations / 2; //(254 * num_iterations /2)
   var binom_deviation = 79687; 
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


component main {public [ challenge,pk ] } = Main(2,3,8000000,10000);

