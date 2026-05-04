pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
// TODO: Include comparators.circom from circomlib to access the `IsZero` component

template Multiplier2Alt () {
  signal input a;
  signal input b;
  signal output c;

  // TODO: Declare the `IsZero` component
  component isZeroCheck = IsZero();
  isZeroCheck.in <== (a - 1) * (b - 1);
  isZeroCheck.out === 0;

  // TODO: If either a or b is 1, input `in` to it should be 0
  // TODO: Make sure output `out` is 0 (false)

  c <== a * b;
}

component main = Multiplier2Alt();