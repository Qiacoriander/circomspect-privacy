pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/escalarmulany.circom";
include "commitment_hasher.circom";
include "elgamal_c1.circom";
include "elgamal_c2.circom";

/*
 * Given commitment, recipent_public_key, c1, and c2, shows that 
 * I know nullifier, secret, and randomness such that
 * - H(nullifier || secret) === commitment
 * - c1 === randomness * BASE8
 * - c2 === randomness * recipent_public_key + H(nullifier)
 * 
 * The commitment is contstrained by the CommitmentHasher circuit.
 * The c1 and c2 are constrained by the ElGamalC1 and ElGamalC2 circuits.
 */
template Deposit() {
  // Public inputs
  signal input commitment; // H(nullifier || secret)
  signal input ciphertext_c1[2]; // randomness * BASE8
  signal input ciphertext_c2[2]; // randomness * recipent_public_key + H(nullifier)
  signal input recipent_public_key[2]; // Public key of the recipent

  // Private inputs
  signal input nullifier;
  signal input secret;
  signal input randomness; // randomness for ElGamal encryption

  component hasher = CommitmentHasher();
  hasher.nullifier <== nullifier;
  hasher.secret <== secret;
  commitment === hasher.commitment;

  signal r_bits[253] <== Num2Bits(253)(randomness);

  signal c1[2] <== ElGamalC1()(random_bits <== r_bits);
  signal c2[2] <== ElGamalC2()(random_bits <== r_bits, recipent_public_key <== recipent_public_key,  message <== hasher.nullifierHash);

  ciphertext_c1 === c1;
  ciphertext_c2 === c2;
}