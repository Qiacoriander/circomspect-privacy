pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template SignMessage (n) {
  signal input identity_secret; 
  signal input identity_commitments[n];
  signal input message;
  signal output signature;

  // Identity commitment
  component identityHasher = Poseidon(1);
  identityHasher.inputs[0] <== identity_secret;
  signal myIdentity <== identityHasher.out;

  // Signature
  component signatureHasher = Poseidon(2);
  signatureHasher.inputs[0] <== identity_secret;
  signatureHasher.inputs[1] <== message;
  signature <== signatureHasher.out;
  log(signature);

  // Membership check
  // Assuming three identities in total
  // TODO: Implement membership check
  // NOTE: We want to prove that our identity is one of the three

  // Sigh what did I learn? That variables are lame
  // Just assign each intermediate value of the variable to a signal instead, and Circom won't scream
  // Literally, just create an array type signal, and just use each index to store new variable values
  signal temp[n + 1];
  temp[0] <== 1;
  for (var i = 1; i < n + 1; i++) {
    temp[i] <== temp[i - 1] * (myIdentity - identity_commitments[i - 1]);
  }
  temp[n] === 0;
}

// Prove that signed a specific message
template Reveal (n) {
  signal input identity_secret; 
  signal input identity_commitments[n];
  signal input message;
  signal input signature;

  // Identity commitment
  component identityHasher = Poseidon(1);
  identityHasher.inputs[0] <== identity_secret;
  signal myIdentity <== identityHasher.out;

  // Signature
  component signatureHasher = Poseidon(2);
  signatureHasher.inputs[0] <== identity_secret;
  signatureHasher.inputs[1] <== message;
  signature === signatureHasher.out;

  // Membership check
  signal temp[n + 1];
  temp[0] <== 1;
  for (var i = 1; i < n + 1; i++) {
    temp[i] <== temp[i - 1] * (myIdentity - identity_commitments[i - 1]);
  }
  temp[n] === 0;
}

template Deny (n) {
  signal input identity_secret; 
  signal input identity_commitments[n];
  signal input message;
  signal input signature;

  // Identity commitment
  component identityHasher = Poseidon(1);
  identityHasher.inputs[0] <== identity_secret;
  signal myIdentity <== identityHasher.out;

  // Signature
  component signatureHasher = Poseidon(2);
  signatureHasher.inputs[0] <== identity_secret;
  signatureHasher.inputs[1] <== message;

  component isZeroCheck = IsZero();
  isZeroCheck.in <== signature - signatureHasher.out;
  isZeroCheck.out === 0;

  // Membership check
  signal temp[n + 1];
  temp[0] <== 1;
  for (var i = 1; i < n + 1; i++) {
    temp[i] <== temp[i - 1] * (myIdentity - identity_commitments[i - 1]);
  }
  temp[n] === 0;
}

component main {public [identity_commitments, message]} = Deny(3);