pragma circom 2.0.3;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template DefendOrb () {
    
    signal input attackEnergy;
    signal input defendEnergy;
    signal input salt;

    signal output attackerEnergyLeft;
    signal output defendHashCheck;
	signal output defenderEnergyLeftH;
	signal output defenderEIsZero;

    signal isAttGreater;
    signal isDefGreater;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== defendEnergy;
    poseidon.inputs[1] <== salt;
    defendHashCheck <== poseidon.out;

    component greaterThan = GreaterThan(7); //max Energy difference 127
    greaterThan.in[0] <== attackEnergy;
    greaterThan.in[1] <== defendEnergy;
    isAttGreater <== greaterThan.out;
    attackerEnergyLeft <== isAttGreater*(attackEnergy-defendEnergy);

	component invert = IsZero();
	invert.in <== isAttGreater;
	isDefGreater <== invert.out;
    component poseidon2 = Poseidon(2);
    poseidon2.inputs[0] <== isDefGreater*(defendEnergy-attackEnergy);
    poseidon2.inputs[1] <== salt;
	defenderEnergyLeftH <== poseidon2.out;
	
	component isZero = IsZero();
	isZero.in <== isDefGreater*(defendEnergy-attackEnergy);
	defenderEIsZero <== isZero.out;
}	

component main { public [ attackEnergy ] } = DefendOrb();