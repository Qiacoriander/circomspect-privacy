pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Condition() {
  signal input in;
  signal output out;
  component n2b = Num2Bits(254);
  n2b.in <== in;

  component isZero = IsZero();
  isZero.in <== n2b.out[0];

  out <== isZero.out * in;

}

template StatfulComputation(n) {

  signal input arr[n];
  signal output i[n];
  signal output arr_out[n];
  signal output acc[n];

  i[0] <== 0;
  acc[0] <== 0;
  arr_out <== arr;

  component conditions[n];

  for(var j = 1; j<n; j++) {
    conditions[j] = Condition();
    conditions[j].in <== arr[j];
    acc[j] <== acc[j - 1] + conditions[j].out;
  }
}

component main = StatfulComputation(5);
