pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template SignMessage () {
  // Private key
  signal input identity_secret; 
  // Public key
  signal input identity_commitment;
  signal input message;
  signal output signature;

  // Identity commitment
  // TODO: Create the identity commitment with Poseidon(1)
  component identityHasher = Poseidon(1);
  identityHasher.inputs[0] <== identity_secret;
  // Enforce commitment = hash(secret)
  identity_commitment === identityHasher.out;

  // Signature
  component signatureHasher = Poseidon(2);
  signatureHasher.inputs[0] <== identity_secret;
  signatureHasher.inputs[1] <== message;
  signature <== signatureHasher.out;
}

// identity_commitment and message will be public outputs, as well as inputs
component main {public [identity_commitment, message]} = SignMessage();