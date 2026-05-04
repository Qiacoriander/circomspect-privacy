pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/bitify.circom";

// Create a circuit that takes a signal and
// rotates it by a given amounnt

template Rotate(n, k) {

  assert(k < n);
  signal input a;
  signal output out;

  component num2bits_a = Num2Bits(n);
  num2bits_a.in <== a;

  signal temp[n];

  for(var i; i < n; i++) {
    temp[i] <== num2bits_a.out[ (i + k) % n];
  }
  
  component bits2num = Bits2Num(n);
  for(var i; i < n; i++) {
    bits2num.in[i] <== temp[i];
  }

  out <== bits2num.out;

}

component main = Rotate(32, 2);