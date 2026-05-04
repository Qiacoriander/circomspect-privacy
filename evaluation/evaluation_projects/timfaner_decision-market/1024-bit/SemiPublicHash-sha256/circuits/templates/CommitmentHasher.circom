pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/poseidon.circom";

template commitmentHasher(){
  signal input secret;
  signal input committerAddr;
  signal output out;

  component hasher = Poseidon(2);
  hasher.inputs[0] <== secret;
  hasher.inputs[1] <== committerAddr;
  out <== hasher.out;
}
