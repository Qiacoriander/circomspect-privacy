
pragma circom 2.1.6;


template BitwiseXOR(n) {
	signal input in[2][n]; // 2 n-bit inputs
	signal output out[n];

  for(var i = 0; i < n; i++) {
    in[0][i] * (in[0][i] - 1) === 0;
    in[1][i] * (in[1][i] - 1) === 0;

    out[i] <== (in[0][i] - in[1][i]) * (in[0][i] - in[1][i]);
  }
}

component main = BitwiseXOR(4);