pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/poseidon.circom";

template NullifierHasher(){
  signal input secret;
  signal input insertedIndex;
  signal output out;

  component hasher = Poseidon(2);
  hasher.inputs[0] <== secret;
  hasher.inputs[1] <== insertedIndex;
  out <== hasher.out;
}