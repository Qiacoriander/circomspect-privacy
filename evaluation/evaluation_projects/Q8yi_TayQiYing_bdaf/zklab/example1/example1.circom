template Multiplier2 () {
  // TODO: Declare the inputs `a` and `b` and output `c`
  // TODO: Constraint `c` to be equal to the product of `a` and `b
  signal input a;
  signal input b;
  signal output c;
  c <== a * b;
}

// TODO: Declare the main component
component main = Multiplier2();