pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template SignMessage () {
  signal input identity_secret; 
  signal input identity_commitment;
  signal input message;
  signal output signature;

  // Identity commitment
  // TODO: Create the identity commitment with Poseidon(1)
  component hasher_commit = Poseidon(1);
  hasher_commit.inputs[0] <== identity_secret;
  identity_commitment === hasher_commit.out;

  // Signature
  // TODO: Create the signature with Poseidon(2)
  component hasher_sig = Poseidon(2);
  hasher_sig.inputs[0] <== identity_secret;
  hasher_sig.inputs[1] <== message;
  signature <== hasher_sig.out;
}

component main {public [identity_commitment, message]} = SignMessage();