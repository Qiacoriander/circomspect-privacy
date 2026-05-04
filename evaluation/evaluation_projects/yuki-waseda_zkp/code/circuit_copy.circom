
include "/home/y.okura/zkp/circomlib/circuits/eddsaposeidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/poseidon.circom";
include "/home/y.okura/zkp/circomlib/circuits/bitify.circom";
include "/home/y.okura/zkp/circomlib/circuits/B2N.circom";



template Main (num, d) {
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


 component hash = Poseidon(3);
 component bitify = Num2Bits_strict();
 hash.inputs[0] <== R8[0];
 hash.inputs[1] <== R8[1];
 hash.inputs[2] <== S;
 bitify.in <== hash.out;
 signal randSeq[254];
 for(var i =0; i < 254; i++){
     randSeq[i] <== bitify.out[i];
 }
  signal rn[num][d];
   var ng = 0;
  for(var i = 0; i < num;i++){
       ng += randSeq[i * d];
      for(var j = 0; j < d; j++){
          rn[i][j]<== randSeq[i * d + j];
      }
  }


  component r[num];
       for (var i = 0; i < num; i++) {
   r[i] =signedBits2Num(d);
       }


  var sum = 0;
  for(var i = 0; i < num; i++){
      for(var j = 0; j < d; j++){
          r[i].in[j] <== rn[i][j];
      }
      sum += r[i].out;
  }
  
  

  signal output comment;
  comment <== 111111111111;
  signal output result;
  result <== sum;
  signal output test;
  var x = 1/100;
  test <== x;
}


component main { public [ challenge,pk ] } = Main(16,8);