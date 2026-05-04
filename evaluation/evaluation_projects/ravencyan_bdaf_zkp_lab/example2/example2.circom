pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

template Multiplier2Alt () {
  signal input a;
  signal input b;
  signal output c;

  component isZeroCheck = IsZero();
  isZeroCheck.in <== (a - 1) * (b - 1);
  isZeroCheck.out === 0;

  c <== a * b;
}

component main = Multiplier2Alt();