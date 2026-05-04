
pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/comparators.circom";

template BitwiseADD(n) {
	
  signal input in[2][n]; // 2 n-bit inputs
	signal output out[n];

  var temp = 0;
  var carry = 0;

  var result = 0;
  for(var i = 0; i < n; i++) {
    in[0][i] * (in[0][i] - 1) === 0;
    in[1][i] * (in[1][i] - 1) === 0;

    temp = in[0][i] + in[1][i] + carry;
    out[i] <-- temp & 1;
    temp = temp >> 1;
    carry = 0;
    while(temp > 0) {
      carry = temp & 1;
      temp = temp >> 1;
    }
    out[i] * (out[i] - 1) === 0;
  }
  

}

component main = BitwiseADD(4);