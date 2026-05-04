pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Z = h(salt|amount|asset)
// N = h(salt+1|amount|asset)

// Need to xorAll = xorExceptZ ^ h(amount|asset|salt) for proving existence of Z in NoxFi contract
// But skip it here :P

template Withdraw() {
  signal input salt;
  // signal input xorExceptZ;
  signal input amount;
  signal input asset;
  // signal input xorAll
  signal output n;

  component poseidon = Poseidon(3);
  poseidon.inputs[0] <-- salt + 1;
  poseidon.inputs[1] <-- amount;
  poseidon.inputs[2] <-- asset;

  n <-- poseidon.out;
}

component main {public [amount, asset]} = Withdraw();
