pragma circom 2.0.0;

// template == object?
template Multiplier2 () {
  // TODO: Declare the inputs `a` and `b` and output `c`
  signal input a;
  signal input b;
  // Output is always public
  signal output c;
  // TODO: Constraint `c` to be equal to the product of `a` and `b
  // i.) Assign c a value, and ii.) Constrain c
  // Constraint - enforce that both sides of the equation must be equal
  c <== a * b;
}

// TODO: Declare the main component
component main = Multiplier2();