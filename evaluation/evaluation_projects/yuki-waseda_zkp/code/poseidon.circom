pragma circom 2.1.6;

// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

//eps = 1

  // 乱数列の数 = 28
  // 必要な乱数列の長さ 486
  // 28 * 486 = 13608ビット
  // ハッシュ列の長さ 254
  // ハッシュへのアクセス回数 54回
include "/home/y.okura/zkp/circomlib/circuits/eddsaposeidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/poseidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/bitify.circom";



template Main (out_dim, in_dim,  sigma) {
  signal input W_delta[out_dim][in_dim]; // 元の更新パラメータの値
  signal input challenge;                // チャレンジの値
  signal input R8[2];                    // 署名の楕円曲線上の点
  signal input S;                        // 署名の値
  signal input pk[2];                    // 公開鍵
  signal input S_clip;  

  // 署名をハッシュ化し、ビット列に変換
  var hash_repeats = 2;
  var hash_length = 254;
  component hash[out_dim][in_dim][hash_repeats];
  component bitify[out_dim][in_dim][hash_repeats];
  signal randSeq[out_dim][in_dim][hash_length * hash_repeats];
  for(var i = 0; i < out_dim; i++){
      for(var j = 0; j < in_dim; j++){
          for(var k = 0; k < hash_repeats; k++){
              hash[i][j][k]=Poseidon(5);
              hash[i][j][k].inputs[0] <== R8[0];
              hash[i][j][k].inputs[1] <== R8[1];
              hash[i][j][k].inputs[2] <== S;
              hash[i][j][k].inputs[3] <== i * in_dim + j;
              hash[i][j][k].inputs[4] <== k;
              bitify[i][j][k] = Num2Bits_strict();
              bitify[i][j][k].in <== hash[i][j][k].out;
              for(var l =0; l < hash_length; l++){
                 randSeq[i][j][k * hash_length + l] <== bitify[i][j][k].out[l];
              }
          }
      }
  }

 
  
}

component main {public [ challenge,pk,S_clip ] } = Main(4,7,10000);