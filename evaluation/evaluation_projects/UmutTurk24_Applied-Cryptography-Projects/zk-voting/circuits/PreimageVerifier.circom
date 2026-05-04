pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";


template PreimageVerifier(nLevels) {
	// Private inputs
	signal input element;
	signal input siblings[nLevels];
	signal input isLeft[nLevels];

	// Public Input
	signal input merkleRoot; // my input

	signal output out;

	component hasher[nLevels];
	component switcher[nLevels];
	signal elements[nLevels];

	switcher[0] = Switcher();
	switcher[0].L <== element;
	switcher[0].R <== siblings[0];
	switcher[0].sel <== isLeft[0];

	hasher[0] = Poseidon(2);
	hasher[0].inputs[0] <== switcher[0].outL;
	hasher[0].inputs[1] <== switcher[0].outR;

	elements[0] <== hasher[0].out;

	for(var i = 1; i < nLevels; i++){
		// Initialize the switcher
		switcher[i] = Switcher();
		switcher[i].L <== elements[i-1];
		switcher[i].R <== siblings[i];
		switcher[i].sel <== isLeft[i];

		// Initialize the hasher
		hasher[i] = Poseidon(2);
		hasher[i].inputs[0] <== switcher[i].outL;
		hasher[i].inputs[1] <== switcher[i].outR;

		elements[i] <== hasher[i].out;
	}
	out <== elements[nLevels-1];

	merkleRoot === out;
}



component main { public [ merkleRoot ] } = PreimageVerifier(2);