pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

// Z = h(salt|amount|asset)
// N = h(salt+1|amount|asset)
// O = h(salt|amount|asset|price)
// ON = h(salt+1|amount|asset|price)

template Settle() {
  signal input salt;
  signal input amount;
  signal input asset;
  signal input price;
  // signal input quantity
  signal input newsalt;
  signal input settlementprice;
  signal output result[3]; // no[0] = o, no[1] = on, no[2] = z
  // need to disconnect between o and new z

  component poseidonO = Poseidon(4);
  poseidonO.inputs[0] <-- salt;
  poseidonO.inputs[1] <-- amount;
  poseidonO.inputs[2] <-- asset;
  poseidonO.inputs[3] <-- price;

  result[0] <-- poseidonO.out;

  component poseidonON = Poseidon(4);
  poseidonON.inputs[0] <-- salt + 1;
  poseidonON.inputs[1] <-- amount;
  poseidonON.inputs[2] <-- asset;
  poseidonON.inputs[3] <-- price;

  result[1] <-- poseidonON.out;

  component poseidonZ = Poseidon(3);
  poseidonZ.inputs[0] <-- newsalt;
  poseidonZ.inputs[1] <-- amount * settlementprice; // only consider ETH -> DAI case
  poseidonZ.inputs[2] <-- (1 - asset);

  result[2] <-- poseidonZ.out;
}

component main { public [settlementprice] } = Settle();
