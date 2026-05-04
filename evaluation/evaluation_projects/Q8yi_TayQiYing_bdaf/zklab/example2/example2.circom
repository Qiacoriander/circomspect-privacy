// TODO: Include comparators.circom from circomlib to access the `IsZero` component
include "circomlib/circuits/comparators.circom";

template Multiplier2Alt () {
  signal input a;
  signal input b;
  signal output c;

  // TODO: Declare the `IsZero` component
  // TODO: If either a or b is 1, input `in` to it should be 0
  // TODO: Make sure output `out` is 0 (false)
  component isZeroCheck = IsZero();
  isZeroCheck.in <== (a - 1) * (b - 1);
  isZeroCheck.out === 0;

  c <== a * b;
}

component main = Multiplier2Alt();