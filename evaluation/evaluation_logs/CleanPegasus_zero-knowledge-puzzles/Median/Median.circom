pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";

template Median() {
  signal input in[5];
  signal input k;

  component lte_1 = LessEqThan(252);
  lte_1.in[0] <== in[0];
  lte_1.in[1] <== in[1];

  component lte_2 = LessEqThan(252);
  lte_2.in[0] <== in[1];
  lte_2.in[1] <== in[2];

  component lte_3 = LessEqThan(252);
  lte_3.in[0] <== in[2];
  lte_3.in[1] <== in[3];

  component lte_4 = LessEqThan(252);
  lte_4.in[0] <== in[3];
  lte_4.in[1] <== in[4];

  signal a;
  signal b;

  a <== lte_1.out * lte_2.out;
  b <== a * lte_3.out;
  1 === b * lte_4.out;

  in[2] === k;

}

component main{public [k]} = Median();