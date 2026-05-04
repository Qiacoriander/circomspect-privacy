pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Deposit() {
  signal input salt;
  signal input amount;
  signal input asset;
  signal output z;

  component poseidon = Poseidon(3);
  poseidon.inputs[0] <== salt;
  poseidon.inputs[1] <== amount;
  poseidon.inputs[2] <== asset;

  z <== poseidon.out;
}

component main {public [amount, asset]} = Deposit();
