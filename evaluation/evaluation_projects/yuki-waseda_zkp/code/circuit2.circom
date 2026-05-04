pragma circom 2.1.6;
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

//eps = 2

  // 乱数列の数 = 28
  // 必要な乱数列の長さ 121
  // 今回生成する長さ 126
  // ハッシュ列の長さ 254
  // ハッシュへのアクセス回数 14回
include "/home/y.okura/zkp/circomlib/circuits/eddsaposeidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/poseidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/bitify.circom";
include "/home/y.okura/zkp/circomlib/circuits/absoluter.circom";

template Main (out_dim, in_dim, S_clip, sigma) {
  signal input W_delta[out_dim][in_dim]; // 元の更新パラメータの値
  signal input challenge;                // チャレンジの値
  signal input R8[2];                    // 署名の楕円曲線上の点
  signal input S;                        // 署名の値
  signal input pk[2];                    // 公開鍵


  // 更新パラメータのクリッピングを検証
  signal W_norm[out_dim * in_dim];
  component abs[out_dim][in_dim];
  for(var i = 0; i < out_dim; i++){
    for(var j = 0; j < in_dim; j++){
        abs[i][j] = Num2abs();
        abs[i][j].in <== W_delta[i][j];
        W_norm[i * in_dim + j] <== (i == 0 && j == 0) ?  abs[i][j].out : W_norm[i * in_dim + j -1] + abs[i][j].out;
    }
  }
  assert(W_norm[out_dim * in_dim - 1] < S_clip);

  // チャレンジへの署名を公開鍵で検証
  component eddsaVerifier = EdDSAPoseidonVerifier();
      eddsaVerifier.Ax <== pk[0];
      eddsaVerifier.Ay <== pk[1];
      eddsaVerifier.S <== S;
      eddsaVerifier.R8x <== R8[0];
      eddsaVerifier.R8y <== R8[1];
      eddsaVerifier.M <== challenge;
      eddsaVerifier.enabled <== 1;

  // 署名をハッシュ化し、ビット列に変換

    component hash[14];
    component bitify[14];
    for(var i = 0; i<14;i++){
        hash[i]=Poseidon(4);
        hash[i].inputs[0] <== R8[0];
        hash[i].inputs[1] <== R8[1];
        hash[i].inputs[2] <== S;
        hash[i].inputs[3] <== i;
        bitify[i]= Num2Bits_strict();
        bitify[i].in <== hash[i].out;
    }

    var hash_length = 254;
    signal randSeq[hash_length * 14];

    for(var i =0; i < 14; i++){
       for(var j = 0; j < hash_length; j++){
           randSeq[hash_length *i + j]<== bitify[i].out[j];
        }
    }

  // ビット列による正規分布の近似
  var binomial_mean = 63;
  signal binomial_sum[out_dim][in_dim][126]; 
  signal centered_binomial_sum[out_dim][in_dim];
   for(var i =0; i < out_dim; i++){
     for(var j = 0; j < in_dim; j++){
        for(var k = 0; k < 126; k++){
            binomial_sum[i][j][k] <== (k == 0) ? randSeq[k + 126 * (in_dim * i + j)] : binomial_sum[i][j][k-1] + randSeq[k + 126 * (in_dim * i + j)];
        }
        centered_binomial_sum[i][j] <== binomial_sum[i][j][126-1] - binomial_mean;
     }
  }

  // 更新パラメータにノイズを付与
  var binomial_scale = 79687;
  signal noise[out_dim][in_dim];
  signal output W_noised[out_dim][in_dim];
  for(var i =0; i < out_dim; i++){
     for(var j = 0; j < in_dim; j++){
         noise[i][j] <== centered_binomial_sum[i][j] * S_clip * sigma;
         W_noised[i][j] <== W_delta[i][j]* binomial_scale + noise[i][j];
     }
  }
}

component main {public [ challenge,pk ] } = Main(4,7,8000000000,10000);