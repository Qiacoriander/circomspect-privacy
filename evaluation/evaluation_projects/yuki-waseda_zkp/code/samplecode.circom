pragma circom 2.1.6;




// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";




//eps = 1




//完成済み




  // 乱数列の数 = 28
  // 必要な乱数列の長さ 486
  // 28 * 486 = 13608ビット
  // ハッシュ列の長さ 254
  // ハッシュへのアクセス回数 54回




include "circomlib/poseidon.circom";      // ポセイドンハッシュ
include "circomlib/bitify.circom";        // ビット変換
include "circomlib/eddsaposeidon.circom"; // 署名の検証




template Num2abs() {
  signal input in;       // 入力値（正または負）
  signal output out;     // 絶対値
   // 符号判定（負の場合に1を返す）
  component isNegative = LessThan(252);
  isNegative.in[0] <== in;
  isNegative.in[1] <== 0;
   // 中間信号を定義
  signal negIn;
  signal posIn;
  signal selectedNeg;
  signal selectedPos;
   negIn <== -in;             // 反転した値
  posIn <== in;              // 正の値
  selectedNeg <== isNegative.out * negIn; // 負の場合の計算
  selectedPos <== (1 - isNegative.out) * posIn; // 正の場合の計算
   // 絶対値を計算
  out <== selectedNeg + selectedPos;
}




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

  // ビット列による正規分布の近似
  var binomial_mean = 254;
  signal binomial_sum[out_dim][in_dim][hash_length * hash_repeats]; 
  signal centered_binomial_sum[out_dim][in_dim];
   for(var i =0; i < out_dim; i++){
     for(var j = 0; j < in_dim; j++){
        for(var k = 0; k < hash_length * hash_repeats; k++){
            binomial_sum[i][j][k] <== (k == 0) ? randSeq[i][j][k] : binomial_sum[i][j][k-1] + randSeq[i][j][k];
        }
        centered_binomial_sum[i][j] <== binomial_sum[i][j][hash_length * hash_repeats-1] - binomial_mean;
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



component main {public [ challenge,pk ] } = Main(2,3,8000000,10000);



/* INPUT = {
  "W_delta":[
      [10000, -10000, 10000],
      [10000, 10000, 10000]
  ],
  "challenge":"77709350291488122190439405240929087353217064205896907018783839224649743200000",
  "R8":[
      "16774387237116105358351138691924953050016913368559223093104495652194631946657",
      "4236017229338829513500649111148409967689382747836787517597021937816281861176"
      ],
  "S":"402445995503813372065504427382289167600771739054294986315426548248231362557",
  "pk":[
      "11437843048345844185793707486483516383500921838036729863808043804720622959984",
      "11024656439251449463892509008176740830119252482644847515994325191124994607993"
  ]
} */