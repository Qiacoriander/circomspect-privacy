pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/poseidon.circom";

include "./circom-ecdsa/eth_addr.circom";

// Verifies:
// - array of owners contains the passed address
// - address belongs to the passed private key
//
// Also generates a nullifier: hash(address, privateKey[0])
//
// o represents the number of owner addresses
// n & k are part of the PrivKeyToAddr component
template NFT (o, n, k) {
  signal input owners[o];
  signal input address;
  signal input privateKey[k];

  // poseidon hash of address + privateKey[0]
  signal input nullifier;
  
  // Verify that the passed address is an owner of a token.
  var accum = 1;
  for (var i = 0; i < o; i++) {
    accum *= owners[i] - address;
  }
  signal temp;
  temp <-- accum;
  component iszero = IsZero();
  iszero.in <== temp;
  iszero.out === 1;

  // verify that the caller knows the private key of the passed address
  component PrivKeyValidator = PrivKeyToAddr(n, k);
  for (var i = 0; i < k; i++) {
    PrivKeyValidator.privkey[i] <== privateKey[i];
  }
  component eq = IsEqual();
  eq.in[0] <== PrivKeyValidator.addr;
  eq.in[1] <== address;
  eq.out === 1;

  // verify that the nullifier is correct
  component hash = Poseidon(2);
  hash.inputs[0] <== address;
  hash.inputs[1] <== privateKey[0];
  nullifier === hash.out;
}

component main {public [owners, nullifier]} = NFT(4, 64, 4);
