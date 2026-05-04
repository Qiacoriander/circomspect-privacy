pragma circom 2.1.6;

// Convert a number to it's corresponding bits. [LSB to MSB]

template Num2Bits(n) {
  signal input num;
  signal output out[n];

  var acc = 0;
  var exp = 1;

  for (var i = 0; i<n; i++) {
    out[i] <-- (num >> i) & 1;
    out[i] * (out[i] - 1) === 0;
    acc += out[i] * exp;
    exp = exp + exp;
  }

  acc === num;
}

component main = Num2Bits(4);
