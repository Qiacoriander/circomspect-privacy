pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/bitify.circom";

// Create a circuit that takes two signals
// and outputs the result with overflow

template MulOverflow(n) {

  signal input a;
  signal input b;
  signal output out;

  signal temp[n];

  signal c <== a * b;

  component num2bits_c = Num2Bits(2 * n);
  num2bits_c.in <== c;
  
  for(var i = 0; i < n; i++) {
    temp[i] <== num2bits_c.out[i];
  }

  component bits2num_temp = Bits2Num(n);
  
  for(var i = 0; i < n; i++) {
    bits2num_temp.in[i] <== temp[i];
  }

  out <== bits2num_temp.out;

}

component main = MulOverflow(32);