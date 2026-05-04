pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Z = h(salt|amount|asset)
// N = h(salt+1|amount|asset)
// O = h(salt|amount|asset|price)

// Need to xorAll = xorExceptZ ^ h(amount|asset|salt) for proving existence of Z in NoxFi contract
// But skip it here :P
// also consider only price of order for clear comprehension

template Order() {
  signal input salt;
  // signal input xorExceptZ;
  signal input amount;
  signal input asset;
  signal input price;
  // signal input quantity
  // signal input xorAll
  signal output no[2]; // no[0] = n, no[1] = o

  component poseidonN = Poseidon(3);
  poseidonN.inputs[0] <-- salt + 1;
  poseidonN.inputs[1] <-- amount;
  poseidonN.inputs[2] <-- asset;

  no[0] <-- poseidonN.out;

  component poseidonO = Poseidon(4);
  poseidonO.inputs[0] <-- salt;
  poseidonO.inputs[1] <-- amount;
  poseidonO.inputs[2] <-- asset;
  poseidonO.inputs[3] <-- price;

  no[1] <-- poseidonO.out;
}

component main = Order();
