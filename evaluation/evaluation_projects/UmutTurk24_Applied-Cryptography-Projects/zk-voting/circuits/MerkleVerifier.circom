pragma circom 2.0.4;
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template MerkleVerifier(nLevels) {
	signal input merkleRoot;
	signal input element;
	signal input siblings[nLevels];
	signal input isLeft[nLevels];

	component hashers[nLevels];
	component switchers[nLevels];
	var current = element;

	for(var i = nLevels - 1; i >= 0; i--) {
		switchers[i] = Switcher();
		switchers[i].sel <== (1 - isLeft[i]);
		switchers[i].L <== current;
		switchers[i].R <== siblings[i];
		hashers[i] = Poseidon(2);
		hashers[i].inputs[0] <== switchers[i].outL;
		hashers[i].inputs[1] <== switchers[i].outR;

		current = hashers[i].out;

	}

	current === merkleRoot;
}
component main { public [ merkleRoot ] } = MerkleVerifier(3);