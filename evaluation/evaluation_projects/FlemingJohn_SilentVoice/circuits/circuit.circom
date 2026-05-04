pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// proves that the prover knows a secret that hashes to a given hash

template Membership() {
  // private input
  signal input secret;

  // public input
  signal output hash;

  // hash the secret using poseidon
  component hasher = Poseidon(1);
  hasher.inputs[0] <== secret;

  // enforce that the hash of the secret is equal to the public hash
  hash <== hasher.out;
}

component main = Membership();