pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/poseidon.circom";

template PublicSignalsHasher(){
  signal input in[9];
  signal output out;

  component hasher1 = Poseidon(3);
  hasher1.inputs[0] <== in[0];
  hasher1.inputs[1] <== in[1];
  hasher1.inputs[2] <== in[2];
  component hasher2 = Poseidon(3);
  hasher2.inputs[0] <== in[3];
  hasher2.inputs[1] <== in[4];
  hasher2.inputs[2] <== in[5];
  component hasher3 = Poseidon(3);
  hasher3.inputs[0] <== in[6];
  hasher3.inputs[1] <== in[7];
  hasher3.inputs[2] <== in[8];
  component hasher4 = Poseidon(3);
  hasher4.inputs[0] <== hasher1.out;
  hasher4.inputs[1] <== hasher2.out;
  hasher4.inputs[2] <== hasher3.out;
  out <== hasher4.out;
}