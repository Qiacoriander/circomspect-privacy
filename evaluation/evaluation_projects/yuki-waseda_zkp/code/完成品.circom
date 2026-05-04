pragma circom 2.1.6;

include "./eddsaposeidon.circom"; // 署名の検証
include "./poseidon.circom";      // ポセイドンハッシュ
include "./bitify.circom";        // ビット変換

template Main (out_dim, in_dim, sigma) {
  signal input W_delta[out_dim][in_dim]; // 更新パラメータの元の値
  signal input S_clip;                   // クリッピング閾値
  signal input challenge;                // チャレンジの値
  signal input R8[2];                    // 署名の楕円曲線上の点
  signal input S;                        // 署名の値
  signal input pk[2];                    // 公開鍵

  // 更新パラメータのクリッピングを検証
  signal W_norm[out_dim * in_dim];
  for(var i = 0; i < out_dim; i++){
    for(var j = 0; j < in_dim; j++){
        W_norm[i * in_dim + j] <== 
            (i == 0 && j == 0) ? W_delta[i][j] ** 2
                               : W_norm[i * in_dim + j - 1] + W_delta[i][j] ** 2;
    }
  }
  assert(W_norm[out_dim * in_dim - 1] <= S_clip ** 2);

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
  var hash_repeats = 2;
  var hash_length = 254;
  component hash[out_dim][in_dim][hash_repeats];
  component bitify[out_dim][in_dim][hash_repeats];
  signal randSeq[out_dim][in_dim][hash_length * hash_repeats];
  for(var i = 0; i < out_dim; i++){
      for(var j = 0; j < in_dim; j++){
          for(var k = 0; k < hash_repeats; k++){
              hash[i][j][k] = Poseidon(5);
              hash[i][j][k].inputs[0] <== R8[0];
              hash[i][j][k].inputs[1] <== R8[1];
              hash[i][j][k].inputs[2] <== S;
              hash[i][j][k].inputs[3] <== i * in_dim + j;
              hash[i][j][k].inputs[4] <== k;
              bitify[i][j][k] = Num2Bits_strict();
              bitify[i][j][k].in <== hash[i][j][k].out;
              for(var l = 0; l < hash_length; l++){
                 randSeq[i][j][k * hash_length + l] <== bitify[i][j][k].out[l];
              }
          }
      }
  }

  // ビット列による正規分布の近似
  var binomial_mean = 254; // 508 * 0.5
  signal binomial_sum[out_dim][in_dim][hash_length * hash_repeats]; 
  signal centered_binomial_sum[out_dim][in_dim];
   for(var i =0; i < out_dim; i++){
     for(var j = 0; j < in_dim; j++){
        for(var k = 0; k < hash_length * hash_repeats; k++){
            binomial_sum[i][j][k] <== 
                (k == 0) ? randSeq[i][j][k] 
                         : binomial_sum[i][j][k-1] + randSeq[i][j][k];
        }
        centered_binomial_sum[i][j] <== 
            binomial_sum[i][j][hash_length * hash_repeats - 1] - binomial_mean;
     }
  }

  // 更新パラメータにノイズを付与
  var binomial_sigma = 1126942766; // sqrt(508 * 0.5 * 0.5) * 10 ^ 8
  signal noise[out_dim][in_dim];
  signal output W_noised[out_dim][in_dim];
  for(var i = 0; i < out_dim; i++){
     for(var j = 0; j < in_dim; j++){
         noise[i][j] <== centered_binomial_sum[i][j] * sigma * S_clip;
         W_noised[i][j] <== W_delta[i][j] * binomial_sigma + noise[i][j];
     }
  }
}

component main {public [S_clip, challenge, pk]} = Main(4, 7, 489647953);